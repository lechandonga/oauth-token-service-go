// Package oauth assembles the local identity & token service: authorization
// code + PKCE login, signed access tokens with rotating keys, and rotating
// refresh tokens backed by durable on-disk state.
package oauth

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal/authcode"
	"github.com/lechandonga/oauth-token-service-go/internal/store"
	"github.com/lechandonga/oauth-token-service-go/internal/token"
)

// Config is the full local configuration of the service.
type Config struct {
	// DataDir holds auth-codes, key ring and session/refresh state.
	DataDir string
	// Issuer is the "iss" claim of access tokens.
	Issuer string
	// Audience is the resource-server audience tokens are minted for.
	Audience string
	// AccessTTL is the access-token lifetime.
	AccessTTL time.Duration
	// RefreshTTL is the refresh-token lifetime (rolling on rotation).
	RefreshTTL time.Duration
	// CodeTTL is the authorization-code lifetime.
	CodeTTL time.Duration
	// Leeway tolerates clock skew when verifying access tokens.
	Leeway time.Duration
	// KeyGraceWindow keeps old signing keys valid after rotation.
	KeyGraceWindow time.Duration
	// Clients maps client_id -> allowed redirect URIs.
	Clients map[string][]string
	// Users maps username -> password for the local login form.
	Users map[string]string
	// Clock is injectable for tests; nil means wall clock.
	Clock func() time.Time
}

func (c *Config) withDefaults() {
	if c.DataDir == "" {
		c.DataDir = filepath.Join(os.TempDir(), "local-oauth-data")
	}
	if c.Issuer == "" {
		c.Issuer = "http://127.0.0.1:8080"
	}
	if c.Audience == "" {
		c.Audience = "local-resource-api"
	}
	if c.AccessTTL <= 0 {
		c.AccessTTL = 15 * time.Minute
	}
	if c.RefreshTTL <= 0 {
		c.RefreshTTL = 7 * 24 * time.Hour
	}
	if c.CodeTTL <= 0 {
		c.CodeTTL = 60 * time.Second
	}
	if c.Leeway <= 0 {
		c.Leeway = 30 * time.Second
	}
	if c.KeyGraceWindow <= 0 {
		c.KeyGraceWindow = 24 * time.Hour
	}
	if c.Clients == nil {
		c.Clients = map[string][]string{
			"local-cli": {"http://127.0.0.1:9876/callback"},
		}
	}
	if c.Users == nil {
		c.Users = map[string]string{"demo": "demo-pass"}
	}
}

// Service is the ready-to-use facade.
type Service struct {
	cfg   Config
	codes *authcode.Manager
	ring  *token.KeyRing
	store *store.SessionStore
	mu    sync.Mutex
}

// New opens (or bootstraps) the service using durable state under DataDir.
func New(cfg Config) (*Service, error) {
	cfg.withDefaults()
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("oauth: data dir: %w", err)
	}

	codeFile := store.NewJSONFile(filepath.Join(cfg.DataDir, "authcodes.json"))
	keyFile := store.NewJSONFile(filepath.Join(cfg.DataDir, "keys.json"))
	sessFile := store.NewJSONFile(filepath.Join(cfg.DataDir, "sessions.json"))

	codes, err := authcode.NewManager(codeFile, authcode.Config{TTL: cfg.CodeTTL}, now)
	if err != nil {
		return nil, err
	}
	ring, err := token.NewKeyRing(keyFile, token.KeyRingConfig{GraceWindow: cfg.KeyGraceWindow}, now)
	if err != nil {
		return nil, err
	}
	sessions, err := store.NewSessionStore(sessFile, now)
	if err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, codes: codes, ring: ring, store: sessions}, nil
}

// Config returns the effective configuration snapshot.
func (s *Service) Config() Config { return s.cfg }

// AuthorizeInput validates the /authorize request and authenticates the user.
type AuthorizeInput struct {
	ResponseType string
	ClientID     string
	RedirectURI  string
	State        string
	Challenge    string
	ChallengeMth string
	Username     string
	Password     string
	Scope        string
}

// Authorize validates client, redirect URI, PKCE and local credentials, then
// issues a one-time code.
func (s *Service) Authorize(in AuthorizeInput) (string, error) {
	if in.ResponseType != "code" {
		return "", ErrUnsupportedResponseType
	}
	if in.ChallengeMth != "" && in.ChallengeMth != "S256" {
		return "", &ServiceError{Code: "invalid_request", Message: "only S256 code_challenge_method is supported"}
	}
	if err := authcode.ValidateRedirectURI(in.RedirectURI); err != nil {
		return "", &ServiceError{Code: "invalid_redirect_uri", Message: err.Error()}
	}
	uris, knownClient := s.cfg.Clients[in.ClientID]
	if !knownClient {
		return "", &ServiceError{Code: "invalid_client", Message: "unknown client_id"}
	}
	if err := authcode.ValidateRegisteredRedirect(uris, in.RedirectURI); err != nil {
		return "", &ServiceError{Code: "invalid_redirect_uri", Message: "redirect_uri not registered for client"}
	}
	if err := authcode.ValidateChallenge(in.Challenge); err != nil {
		return "", &ServiceError{Code: "invalid_request", Message: err.Error()}
	}
	if !s.checkUser(in.Username, in.Password) {
		return "", ErrInvalidCredentials
	}
	code, err := s.codes.Issue(authcode.IssueParams{
		ClientID:    in.ClientID,
		RedirectURI: in.RedirectURI,
		Challenge:   in.Challenge,
		Subject:     in.Username,
		Scope:       in.Scope,
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

func (s *Service) checkUser(user, pass string) bool {
	want, ok := s.cfg.Users[user]
	return ok && want == pass
}

// TokenBundle is the result of a code exchange or a refresh.
type TokenBundle struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64
	SessionID    string
	Scope        string
}

// ExchangeInput are the token-endpoint parameters for authorization_code.
type ExchangeInput struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	CodeVerifier string
	RefreshToken string
}

// Token handles both authorization_code and refresh_token grants.
func (s *Service) Token(in ExchangeInput) (*TokenBundle, error) {
	switch in.GrantType {
	case "authorization_code":
		return s.exchangeCode(in)
	case "refresh_token":
		return s.refresh(in.RefreshToken)
	default:
		return nil, ErrUnsupportedGrantType
	}
}

func (s *Service) exchangeCode(in ExchangeInput) (*TokenBundle, error) {
	ac, err := s.codes.Exchange(authcode.ExchangeParams{
		Code:         in.Code,
		ClientID:     in.ClientID,
		RedirectURI:  in.RedirectURI,
		CodeVerifier: in.CodeVerifier,
	})
	if err != nil {
		return nil, mapCodeError(err)
	}

	sid, refresh, err := s.store.CreateSession(ac.Subject, ac.ClientID, ac.Scope, s.cfg.RefreshTTL)
	if err != nil {
		return nil, err
	}
	access, err := s.signAccess(sid, ac.Subject, ac.Scope)
	if err != nil {
		return nil, err
	}
	return &TokenBundle{
		AccessToken: access, RefreshToken: refresh, TokenType: "Bearer",
		ExpiresIn: int64(s.cfg.AccessTTL.Seconds()), SessionID: sid, Scope: ac.Scope,
	}, nil
}

func (s *Service) refresh(raw string) (*TokenBundle, error) {
	res, err := s.store.Rotate(raw, s.cfg.RefreshTTL)
	if err != nil {
		return nil, mapStoreError(err)
	}
	access, err := s.signAccess(res.Session.ID, res.Session.Subject, res.Session.Scope)
	if err != nil {
		return nil, err
	}
	return &TokenBundle{
		AccessToken: access, RefreshToken: res.NewRefresh, TokenType: "Bearer",
		ExpiresIn: int64(s.cfg.AccessTTL.Seconds()), SessionID: res.Session.ID, Scope: res.Session.Scope,
	}, nil
}

func (s *Service) signAccess(sid, subject, scope string) (string, error) {
	now := time.Now()
	if s.cfg.Clock != nil {
		now = s.cfg.Clock()
	}
	return s.ring.Sign(token.Claims{
		Issuer:    s.cfg.Issuer,
		Subject:   subject,
		Audience:  token.Audience{s.cfg.Audience},
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: now.Add(s.cfg.AccessTTL).Unix(),
		SessionID: sid,
		Scope:     scope,
	})
}

// VerifyResult exposes validated token content.
type VerifyResult struct {
	Subject string
	Session string
	Scope   string
}

// Verify checks signature/claims and confirms the backing session is alive.
func (s *Service) Verify(accessToken string) (*VerifyResult, error) {
	claims, err := s.ring.Verify(accessToken, token.VerifyOptions{
		Issuer:   s.cfg.Issuer,
		Audience: s.cfg.Audience,
		Leeway:   s.cfg.Leeway,
		Now:      s.cfg.Clock,
	})
	if err != nil {
		return nil, mapTokenError(err)
	}
	if !s.store.SessionActive(claims.SessionID) {
		return nil, ErrSessionRevoked
	}
	return &VerifyResult{Subject: claims.Subject, Session: claims.SessionID, Scope: claims.Scope}, nil
}

// Logout revokes a session and therefore all its tokens.
func (s *Service) Logout(sessionID string) error {
	return s.store.RevokeSession(sessionID, "logout")
}

// Revoke revokes the family of a presented refresh token (RFC 7009).
func (s *Service) Revoke(refreshToken string) error {
	return s.store.RevokeRefresh(refreshToken, "revocation_endpoint")
}

// RotateKeys performs a signing-key rotation with the configured grace window.
func (s *Service) RotateKeys() error {
	_, err := s.ring.Rotate()
	return err
}

// CurrentKeyID returns the active signing key id (diagnostics).
func (s *Service) CurrentKeyID() string { return s.ring.CurrentKeyID() }

// AuditEvents exposes the security audit trail.
func (s *Service) AuditEvents() []store.AuditEvent { return s.store.Events() }

// RedirectURIAllowed reports whether a URI is registered for the client.
func (s *Service) RedirectURIAllowed(clientID, redirect string) bool {
	for _, u := range s.cfg.Clients[clientID] {
		if u == redirect {
			return true
		}
	}
	return false
}

// SafeRedirectError reports whether an error relates to an untrusted redirect
// (in which case the response must not redirect back).
func SafeRedirectError(err error) bool {
	var se *ServiceError
	return errors.As(err, &se) && (se.Code == "invalid_redirect_uri" || se.Code == "invalid_client")
}

func mapCodeError(err error) error {
	return &ServiceError{Code: authcode.ErrorCode(err), Message: err.Error(), Cause: err}
}

func mapStoreError(err error) error {
	switch {
	case errors.Is(err, store.ErrRefreshNotFound):
		return &ServiceError{Code: "invalid_grant", Message: "unknown refresh token", Cause: err}
	case errors.Is(err, store.ErrRefreshExpired):
		return &ServiceError{Code: "invalid_grant", Message: "refresh token expired", Cause: err}
	case errors.Is(err, store.ErrRefreshUsed):
		return &ServiceError{Code: "invalid_grant", Message: "refresh token already used; token family revoked", Cause: err}
	case errors.Is(err, store.ErrFamilyRevoked), errors.Is(err, store.ErrSessionRevoked):
		return &ServiceError{Code: "invalid_grant", Message: "token family revoked", Cause: err}
	default:
		return &ServiceError{Code: "server_error", Message: "token operation failed", Cause: err}
	}
}

func mapTokenError(err error) error {
	return &ServiceError{Code: token.ErrorCode(err), Message: safeTokenMessage(err), Cause: err}
}

// safeTokenMessage avoids leaking low-level crypto/encoding errors.
func safeTokenMessage(err error) string {
	switch {
	case errors.Is(err, token.ErrMalformed):
		return "malformed access token"
	case errors.Is(err, token.ErrSignature):
		return "token signature verification failed"
	case errors.Is(err, token.ErrNoValidKey):
		return "token signed by an unknown or expired key"
	case errors.Is(err, token.ErrTokenExpired):
		return "access token expired"
	case errors.Is(err, token.ErrNotYetValid):
		return "access token not valid yet"
	case errors.Is(err, token.ErrIssuerMismatch):
		return "token issuer mismatch"
	case errors.Is(err, token.ErrAudienceMissing):
		return "token audience mismatch"
	default:
		return "access token rejected"
	}
}

// BuildCallbackURL appends code and state to a validated redirect URI.
func BuildCallbackURL(redirect, code, state string) string {
	u, err := url.Parse(redirect)
	if err != nil {
		return redirect
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
