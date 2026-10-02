package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Distinguishable refresh/session failures.
var (
	ErrRefreshNotFound = errors.New("store: refresh token not found")
	ErrRefreshExpired  = errors.New("store: refresh token expired")
	ErrRefreshUsed     = errors.New("store: refresh token already rotated")
	ErrFamilyRevoked   = errors.New("store: refresh token family revoked")
	ErrSessionRevoked  = errors.New("store: session revoked")
)

// Session is one authenticated subject login, identified by a family id.
type Session struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject"`
	ClientID  string    `json:"client_id"`
	Scope     string    `json:"scope"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
	Revoked   bool      `json:"revoked"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

// RefreshToken is a single node in a session's rotation chain. Only raw
// SHA-256 hashes of tokens are stored.
type RefreshToken struct {
	Hash        string    `json:"hash"`
	SessionID   string    `json:"session_id"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Rotated     bool      `json:"rotated"`
	RotatedAt   time.Time `json:"rotated_at,omitempty"`
	Revoked     bool      `json:"revoked"`
	RevokedAt   time.Time `json:"revoked_at,omitempty"`
	ReuseSeen   bool      `json:"reuse_seen,omitempty"`
	ReuseSeenAt time.Time `json:"reuse_seen_at,omitempty"`
}

// AuditEvent records a security-relevant state transition.
type AuditEvent struct {
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`
	SessionID string    `json:"session_id,omitempty"`
	TokenHash string    `json:"token_hash,omitempty"`
	Detail    string    `json:"detail,omitempty"`
}

type sessionsDoc struct {
	Sessions map[string]*Session      `json:"sessions"`
	Tokens   map[string]*RefreshToken `json:"tokens"`
	Events   []AuditEvent             `json:"events"`
}

// SessionStore keeps sessions, refresh token chains and the audit trail.
type SessionStore struct {
	persist  *JSONFile
	now      func() time.Time
	maxEvent int

	mu       sync.Mutex
	sessions map[string]*Session
	tokens   map[string]*RefreshToken
	events   []AuditEvent
}

// NewSessionStore restores persisted state (survives process restarts).
func NewSessionStore(persist *JSONFile, now func() time.Time) (*SessionStore, error) {
	if now == nil {
		now = time.Now
	}
	s := &SessionStore{persist: persist, now: now, maxEvent: 2000,
		sessions: map[string]*Session{}, tokens: map[string]*RefreshToken{}}
	var doc sessionsDoc
	if err := persist.Load(&doc); err != nil {
		return nil, fmt.Errorf("store: load sessions: %w", err)
	}
	if doc.Sessions != nil {
		s.sessions = doc.Sessions
	}
	if doc.Tokens != nil {
		s.tokens = doc.Tokens
	}
	s.events = doc.Events
	return s, nil
}

// HashToken returns the stored fingerprint of an opaque token.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *SessionStore) saveLocked() error {
	return s.persist.Save(sessionsDoc{
		Sessions: s.sessions,
		Tokens:   s.tokens,
		Events:   s.events,
	})
}

func (s *SessionStore) auditLocked(kind, sessionID, tokenHash, detail string) {
	ev := AuditEvent{Time: s.now(), Kind: kind, SessionID: sessionID, TokenHash: tokenHash, Detail: detail}
	s.events = append(s.events, ev)
	if len(s.events) > s.maxEvent {
		s.events = s.events[len(s.events)-s.maxEvent:]
	}
}

// Events returns a copy of the audit trail (newest last).
func (s *SessionStore) Events() []AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AuditEvent, len(s.events))
	copy(out, s.events)
	return out
}

// CreateSession opens a session and returns its id plus the first opaque
// refresh token. The raw token is shown only once.
func (s *SessionStore) CreateSession(subject, clientID, scope string, ttl time.Duration) (sessionID, refreshToken string, err error) {
	sid, err := newID()
	if err != nil {
		return "", "", err
	}
	raw, err := newOpaqueToken()
	if err != nil {
		return "", "", err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sid] = &Session{
		ID: sid, Subject: subject, ClientID: clientID, Scope: scope,
		CreatedAt: now, LastUsed: now,
	}
	s.tokens[HashToken(raw)] = &RefreshToken{
		Hash: HashToken(raw), SessionID: sid,
		IssuedAt: now, ExpiresAt: now.Add(ttl),
	}
	s.auditLocked("session_created", sid, "", "subject="+subject)
	if err := s.saveLocked(); err != nil {
		return "", "", err
	}
	return sid, raw, nil
}

// RotateResult describes one successful refresh rotation.
type RotateResult struct {
	Session *Session
	// NewRefresh is the raw replacement refresh token (shown once).
	NewRefresh string
}

// Rotate consumes a refresh token and issues a replacement. Presenting an
// already-rotated token is treated as theft: the whole family is revoked.
// Concurrent rotation of the same token yields exactly one success.
func (s *SessionStore) Rotate(raw string, ttl time.Duration) (*RotateResult, error) {
	hash := HashToken(raw)
	newRaw, err := newOpaqueToken()
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rt, ok := s.tokens[hash]
	if !ok {
		// Unknown token: no family to revoke, still leave a trace.
		s.auditLocked("refresh_unknown", "", hash, "")
		_ = s.saveLocked()
		return nil, ErrRefreshNotFound
	}
	sess := s.sessions[rt.SessionID]
	now := s.now()

	if rt.ReuseSeen || rt.Rotated || rt.Revoked || (sess != nil && sess.Revoked) {
		alreadyRevoked := sess != nil && sess.Revoked
		var replayErr error
		switch {
		case alreadyRevoked, rt.Revoked:
			replayErr = ErrFamilyRevoked
		default:
			replayErr = ErrRefreshUsed
		}
		// Reuse / family already dead -> revoke everything if not already.
		reason := "reused_refresh_token"
		switch {
		case alreadyRevoked:
			reason = sess.Reason
		case rt.Revoked:
			reason = "token_revoked"
		}
		if !rt.ReuseSeen {
			rt.ReuseSeen = true
			rt.ReuseSeenAt = now
		}
		s.revokeFamilyLocked(rt.SessionID, reason)
		if err := s.saveLocked(); err != nil {
			return nil, err
		}
		return nil, replayErr
	}
	if !now.Before(rt.ExpiresAt) {
		rt.Revoked = true
		rt.RevokedAt = now
		s.auditLocked("refresh_expired", rt.SessionID, hash, "")
		_ = s.saveLocked()
		return nil, ErrRefreshExpired
	}

	// Valid use: rotate the node and append the successor to the chain.
	rt.Rotated = true
	rt.RotatedAt = now
	sess.LastUsed = now
	nextHash := HashToken(newRaw)
	s.tokens[nextHash] = &RefreshToken{
		Hash: nextHash, SessionID: rt.SessionID,
		IssuedAt: now, ExpiresAt: now.Add(ttl),
	}
	s.auditLocked("refresh_rotated", rt.SessionID, hash, "successor="+nextHash)
	if err := s.saveLocked(); err != nil {
		// Roll back so an I/O failure does not silently desync state.
		rt.Rotated = false
		rt.RotatedAt = time.Time{}
		sess.LastUsed = now
		delete(s.tokens, nextHash)
		return nil, fmt.Errorf("store: persist rotation: %w", err)
	}
	return &RotateResult{Session: sess, NewRefresh: newRaw}, nil
}

// revokeFamilyLocked marks the session and every chain token revoked.
func (s *SessionStore) revokeFamilyLocked(sid, reason string) {
	sess, ok := s.sessions[sid]
	if !ok {
		return
	}
	if !sess.Revoked {
		sess.Revoked = true
		sess.RevokedAt = s.now()
		sess.Reason = reason
	}
	for _, rt := range s.tokens {
		if rt.SessionID == sid && !rt.Revoked {
			rt.Revoked = true
			rt.RevokedAt = s.now()
		}
	}
	s.auditLocked("family_revoked", sid, "", reason)
}

// RevokeSession logs the user out: session and all access/refresh tokens die.
func (s *SessionStore) RevokeSession(sid, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[sid]; !ok {
		return fmt.Errorf("store: unknown session %q", sid)
	}
	s.revokeFamilyLocked(sid, reason)
	s.auditLocked("logout", sid, "", reason)
	return s.saveLocked()
}

// RevokeRefresh revokes the whole family of a presented refresh token
// (RFC 7009 semantics for this local deployment).
func (s *SessionStore) RevokeRefresh(raw, reason string) error {
	hash := HashToken(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.tokens[hash]
	if !ok {
		s.auditLocked("revoke_unknown", "", hash, reason)
		return s.saveLocked()
	}
	s.revokeFamilyLocked(rt.SessionID, reason)
	return s.saveLocked()
}

// SessionActive reports whether an access token's session is still valid.
func (s *SessionStore) SessionActive(sid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sid]
	return ok && !sess.Revoked
}

// Session returns a snapshot of a session.
func (s *SessionStore) Session(sid string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sid]
	if !ok {
		return nil, false
	}
	cp := *sess
	return &cp, true
}
