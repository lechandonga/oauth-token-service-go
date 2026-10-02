package oauth

import (
	"encoding/json"
	"html"
	"log"
	"net/http"
	"strings"

	"github.com/lechandonga/oauth-token-service-go/internal/authcode"
)

// Handler returns the HTTP mux exposing the local OAuth endpoints:
//
//	GET  /healthz
//	GET  /authorize        login form
//	POST /authorize        authenticate + issue code (302 redirect)
//	POST /token            authorization_code / refresh_token
//	GET  /introspect       Bearer token verification
//	POST /revoke           RFC 7009 refresh-token revocation
//	POST /logout           revoke session by Bearer access token
//	GET  /.well-known/openid-configuration-style discovery doc (/metadata)
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /metadata", s.handleMetadata)
	mux.HandleFunc("GET /authorize", s.handleLoginForm)
	mux.HandleFunc("POST /authorize", s.handleAuthorize)
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("GET /introspect", s.handleIntrospect)
	mux.HandleFunc("POST /revoke", s.handleRevoke)
	mux.HandleFunc("POST /logout", s.handleLogout)
	return s.withLogging(mux)
}

func (s *Service) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		log.Printf("%s %s", r.Method, r.URL.Path)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func tokenError(w http.ResponseWriter, status int, err error) {
	se, ok := err.(*ServiceError)
	if !ok {
		writeJSON(w, status, map[string]string{"error": "server_error", "error_description": "internal error"})
		return
	}
	writeJSON(w, status, map[string]string{"error": se.Code, "error_description": se.Message})
}

func (s *Service) handleMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                           s.cfg.Issuer,
		"authorization_endpoint":           s.cfg.Issuer + "/authorize",
		"token_endpoint":                   s.cfg.Issuer + "/token",
		"introspection_endpoint":           s.cfg.Issuer + "/introspect",
		"revocation_endpoint":              s.cfg.Issuer + "/revoke",
		"code_challenge_methods_supported": []string{"S256"},
		"grant_types_supported":            []string{"authorization_code", "refresh_token"},
	})
}

const loginPage = `<!doctype html><meta charset=utf-8>
<title>Local OAuth Login</title>
<style>body{font-family:system-ui;max-width:34rem;margin:3rem auto}input{width:100%;padding:.5rem;margin:.25rem 0 .8rem}</style>
<h2>Local sign-in</h2>
<p style="color:#666">Authorization code + PKCE. Local accounts only.</p>
%s
<form method=post action=/authorize>
<input type=hidden name=response_type value=code>
<input type=hidden name=client_id value=%q>
<input type=hidden name=redirect_uri value=%q>
<input type=hidden name=state value=%q>
<input type=hidden name=code_challenge value=%q>
<input type=hidden name=code_challenge_method value=S256>
<input type=hidden name=scope value=%q>
<label>Username <input name=username autocomplete=username required></label>
<label>Password <input name=password type=password autocomplete=current-password required></label>
<button>Sign in</button>
</form>`

func (s *Service) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	in := AuthorizeInput{
		ResponseType: q.Get("response_type"),
		ClientID:     q.Get("client_id"),
		RedirectURI:  q.Get("redirect_uri"),
		State:        q.Get("state"),
		Challenge:    q.Get("code_challenge"),
		ChallengeMth: q.Get("code_challenge_method"),
		Scope:        q.Get("scope"),
	}
	if in.ResponseType != "code" {
		http.Error(w, "response_type must be code", http.StatusBadRequest)
		return
	}
	if err := authcode.ValidateRedirectURI(in.RedirectURI); err != nil {
		http.Error(w, "invalid redirect_uri: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !s.RedirectURIAllowed(in.ClientID, in.RedirectURI) {
		http.Error(w, "client_id or redirect_uri not registered", http.StatusBadRequest)
		return
	}
	if err := authcode.ValidateChallenge(in.Challenge); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(renderLogin(loginPage, "", in)))
}

func (s *Service) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	in := AuthorizeInput{
		ResponseType: r.PostForm.Get("response_type"),
		ClientID:     r.PostForm.Get("client_id"),
		RedirectURI:  r.PostForm.Get("redirect_uri"),
		State:        r.PostForm.Get("state"),
		Challenge:    r.PostForm.Get("code_challenge"),
		ChallengeMth: r.PostForm.Get("code_challenge_method"),
		Username:     r.PostForm.Get("username"),
		Password:     r.PostForm.Get("password"),
		Scope:        r.PostForm.Get("scope"),
	}
	code, err := s.Authorize(in)
	if err != nil {
		if SafeRedirectError(err) {
			// Never redirect to an unvalidated URI.
			tokenError(w, http.StatusBadRequest, err)
			return
		}
		page := loginPage
		msg := `<p style="color:#b00">` + html.EscapeString(err.Error()) + `</p>`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(renderLogin(page, msg, in)))
		return
	}
	http.Redirect(w, r, BuildCallbackURL(in.RedirectURI, code, in.State), http.StatusSeeOther)
}

func (s *Service) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, &ServiceError{Code: "invalid_request", Message: "malformed form"})
		return
	}
	// Public PKCE clients: accept client_id from body; also allow Basic.
	clientID := r.PostForm.Get("client_id")
	if u, p, ok := r.BasicAuth(); ok {
		clientID = u
		_ = p
	}
	bundle, err := s.Token(ExchangeInput{
		GrantType:    r.PostForm.Get("grant_type"),
		Code:         r.PostForm.Get("code"),
		RedirectURI:  r.PostForm.Get("redirect_uri"),
		ClientID:     clientID,
		CodeVerifier: r.PostForm.Get("code_verifier"),
		RefreshToken: r.PostForm.Get("refresh_token"),
	})
	if err != nil {
		tokenError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  bundle.AccessToken,
		"refresh_token": bundle.RefreshToken,
		"token_type":    bundle.TokenType,
		"expires_in":    bundle.ExpiresIn,
		"scope":         bundle.Scope,
	})
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer "), true
	}
	// Introspection may also pass the token as query/form for local testing.
	if t := r.URL.Query().Get("token"); t != "" {
		return t, true
	}
	return "", false
}

func (s *Service) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	raw, ok := bearer(r)
	if !ok || raw == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"active": false, "error": "missing_bearer_token"})
		return
	}
	res, err := s.Verify(raw)
	if err != nil {
		se, _ := err.(*ServiceError)
		code := "rejected"
		if se != nil {
			code = se.Code
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"active": false, "error": code})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active": true,
		"sub":    res.Subject,
		"sid":    res.Session,
		"scope":  res.Scope,
	})
}

func (s *Service) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, &ServiceError{Code: "invalid_request", Message: "malformed form"})
		return
	}
	if t := r.PostForm.Get("token"); t != "" {
		if err := s.Revoke(t); err != nil {
			tokenError(w, http.StatusBadRequest, err)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	raw, ok := bearer(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_bearer_token"})
		return
	}
	res, err := s.Verify(raw)
	if err != nil {
		tokenError(w, http.StatusUnauthorized, err)
		return
	}
	if err := s.Logout(res.Session); err != nil {
		tokenError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}
