// Package authcode implements the OAuth 2.0 authorization-code grant with
// PKCE (RFC 7636, S256 only). Codes are one-time, short-lived, and bound to
// the client id, redirect uri and code challenge issued at authorization.
package authcode

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal/store"
)

// Code is the persisted record of an issued authorization code.
type Code struct {
	ID            string    `json:"id"`
	ClientID      string    `json:"client_id"`
	RedirectURI   string    `json:"redirect_uri"`
	Challenge     string    `json:"challenge"`
	ChallengeMeth string    `json:"challenge_method"`
	Subject       string    `json:"subject"`
	Scope         string    `json:"scope"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Used          bool      `json:"used"`
	UsedAt        time.Time `json:"used_at,omitempty"`
}

// Config tunes code lifetime and code length.
type Config struct {
	TTL time.Duration
}

func (c Config) ttl() time.Duration {
	if c.TTL <= 0 {
		return 60 * time.Second
	}
	return c.TTL
}

// Manager issues and exchanges authorization codes. All operations are
// serialized internally so concurrent exchanges of the same code have exactly
// one winner.
type Manager struct {
	persist *store.JSONFile
	cfg     Config
	now     func() time.Time

	mu    sync.Mutex
	codes map[string]*Code
}

// NewManager restores previously issued codes from file (if any).
func NewManager(persist *store.JSONFile, cfg Config, now func() time.Time) (*Manager, error) {
	if now == nil {
		now = time.Now
	}
	m := &Manager{persist: persist, cfg: cfg, now: now, codes: map[string]*Code{}}

	var doc struct {
		Codes []*Code `json:"codes"`
	}
	if err := persist.Load(&doc); err != nil {
		return nil, fmt.Errorf("authcode: load state: %w", err)
	}
	for _, c := range doc.Codes {
		m.codes[c.ID] = c
	}
	return m, nil
}

func randomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// IssueParams are the validated inputs for issuing a code.
type IssueParams struct {
	ClientID    string
	RedirectURI string
	Challenge   string
	Subject     string
	Scope       string
}

// ValidateClientAndRedirect is the local client registry check. Only
// pre-registered clients with an exact redirect URI match receive codes.
func ValidateClientAndRedirect(clients map[string][]string, clientID, redirectURI string) error {
	uris, ok := clients[clientID]
	if !ok {
		return errors.New("authcode: unknown client_id")
	}
	return ValidateRegisteredRedirect(uris, redirectURI)
}

// ValidateRegisteredRedirect checks a redirect against a client's allow list.
func ValidateRegisteredRedirect(allowedURIs []string, redirectURI string) error {
	for _, allowed := range allowedURIs {
		if allowed == redirectURI {
			return nil
		}
	}
	return errors.New("authcode: unregistered redirect_uri")
}

// ValidateChallenge checks a PKCE S256 code_challenge (base64url(SHA256), no pad).
func ValidateChallenge(challenge string) error {
	if challenge == "" {
		return errors.New("authcode: missing code_challenge")
	}
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(raw) != sha256.Size {
		return errors.New("authcode: code_challenge must be base64url(SHA-256), 43 chars")
	}
	return nil
}

// ValidateRedirectURI only accepts http(s) loopback for this local deployment.
func ValidateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("authcode: invalid redirect_uri")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("authcode: redirect_uri must use http or https")
	}
	if u.Fragment != "" || u.RawQuery != "" {
		return errors.New("authcode: redirect_uri must not contain query or fragment")
	}
	host := u.Hostname()
	if host != "localhost" && host != "127.0.0.1" && host != "[::1]" {
		return errors.New("authcode: redirect_uri host must be loopback")
	}
	return nil
}

// Issue creates a new one-time code.
func (m *Manager) Issue(p IssueParams) (string, error) {
	if err := ValidateChallenge(p.Challenge); err != nil {
		return "", err
	}
	if p.ClientID == "" || p.RedirectURI == "" || p.Subject == "" {
		return "", errors.New("authcode: client_id, redirect_uri and subject are required")
	}
	id, err := randomToken(32)
	if err != nil {
		return "", err
	}
	now := m.now()
	c := &Code{
		ID:            id,
		ClientID:      p.ClientID,
		RedirectURI:   p.RedirectURI,
		Challenge:     p.Challenge,
		ChallengeMeth: "S256",
		Subject:       p.Subject,
		Scope:         p.Scope,
		IssuedAt:      now,
		ExpiresAt:     now.Add(m.cfg.ttl()),
	}
	m.mu.Lock()
	m.codes[id] = c
	err = m.saveLocked()
	m.mu.Unlock()
	if err != nil {
		return "", err
	}
	return id, nil
}

// Exchange consumes a code after checking identity, parameters and PKCE.
type ExchangeParams struct {
	Code         string
	ClientID     string
	RedirectURI  string
	CodeVerifier string
}

// Exchange validates and consumes a code. On success the returned Code is the
// snapshot bound to the authorization request. A code can be consumed once.
func (m *Manager) Exchange(p ExchangeParams) (*Code, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.codes[p.Code]
	if !ok {
		return nil, ErrCodeNotFound
	}

	// Every failed presentation of a one-time code also marks it used so a
	// later (possibly corrected) replay cannot succeed.
	fail := func(err error) error {
		if !c.Used {
			c.Used = true
			c.UsedAt = m.now()
			_ = m.saveLocked()
		}
		return err
	}

	if c.Used {
		return nil, ErrCodeAlreadyUsed
	}
	now := m.now()
	if !now.Before(c.ExpiresAt) {
		return nil, fail(ErrCodeExpired)
	}
	if c.ClientID != p.ClientID || c.RedirectURI != p.RedirectURI {
		return nil, fail(ErrParameterMismatch)
	}
	if c.ChallengeMeth != "S256" || !verifyS256(c.Challenge, p.CodeVerifier) {
		return nil, fail(ErrPKCEMismatch)
	}

	c.Used = true
	c.UsedAt = now
	if err := m.saveLocked(); err != nil {
		c.Used = false
		c.UsedAt = time.Time{}
		return nil, fmt.Errorf("authcode: persist consumption: %w", err)
	}

	snapshot := *c
	return &snapshot, nil
}

func verifyS256(challenge, verifier string) bool {
	// RFC 7636: verifier is 43..128 unreserved chars; challenge is
	// BASE64URL-ENCODE(SHA256(ASCII(verifier))).
	if n := len(verifier); n < 43 || n > 128 {
		return false
	}
	for _, r := range verifier {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~", r) {
			return false
		}
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

func (m *Manager) saveLocked() error {
	doc := struct {
		Codes []*Code `json:"codes"`
	}{}
	for _, c := range m.codes {
		doc.Codes = append(doc.Codes, c)
	}
	return m.persist.Save(doc)
}

// S256Challenge computes the challenge for a given verifier (helper for
// clients/tests).
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
