// Package server 把授权码、访问令牌、刷新令牌各模块装配成
// 一个仅监听本地回环地址的 HTTP 服务。
package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal"
	"github.com/lechandonga/oauth-token-service-go/internal/authcode"
	"github.com/lechandonga/oauth-token-service-go/internal/config"
	"github.com/lechandonga/oauth-token-service-go/internal/refresh"
	"github.com/lechandonga/oauth-token-service-go/internal/store"
	"github.com/lechandonga/oauth-token-service-go/internal/token"
)

// Server 持有全部运行期组件。
type Server struct {
	cfg    config.Config
	store  *store.Store
	codes  *authcode.Manager
	tokens *token.Manager
	fresh  *refresh.Service
	now    func() time.Time
}

// New 装配服务。
func New(cfg config.Config, st *store.Store, now func() time.Time) *Server {
	if now == nil {
		now = time.Now
	}
	return &Server{
		cfg:    cfg,
		store:  st,
		codes:  authcode.NewManager(cfg.CodeTTL.Std(), now),
		tokens: token.NewManager(st, cfg.Issuer, cfg.Audience, cfg.KeyGraceWindow.Std(), cfg.ClockSkewLeeway.Std(), now),
		fresh:  refresh.NewService(st, cfg.RefreshTokenTTL.Std(), now),
		now:    now,
	}
}

// Routes 注册路由。
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/verify", s.handleVerify)
	mux.HandleFunc("/revoke", s.handleRevoke)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/admin/rotate", s.handleRotate)
	mux.HandleFunc("/audit", s.handleAudit)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, "ok")
	})
	return mux
}

func writeErr(w http.ResponseWriter, status int, code internal.ErrorCode, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": string(code), "error_description": desc})
}

func statusFor(code internal.ErrorCode) int {
	if code == internal.CodeUnauthorizedClient {
		return http.StatusUnauthorized
	}
	return http.StatusBadRequest
}

// authenticateClient 用 HTTP Basic Auth 校验 client_id/secret。
func (s *Server) authenticateClient(r *http.Request) (config.Client, bool) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		return config.Client{}, false
	}
	cl, exists := s.cfg.ClientByID(id)
	if !exists {
		return config.Client{}, false
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(cl.Secret)) != 1 {
		return config.Client{}, false
	}
	return cl, true
}

// handleAuthorize 同时承载登录表单（GET）与登录提交（POST）。
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	q := r.Form
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	challenge := q.Get("code_challenge")
	state := q.Get("state")

	cl, exists := s.cfg.ClientByID(clientID)
	if !exists {
		writeErr(w, http.StatusBadRequest, internal.CodeUnauthorizedClient, "unknown client_id")
		return
	}
	if redirectURI == "" || !cl.HasRedirect(redirectURI) {
		writeErr(w, http.StatusBadRequest, internal.CodeInvalidRedirect, "unregistered redirect_uri")
		return
	}
	if q.Get("response_type") != "code" {
		writeErr(w, http.StatusBadRequest, internal.CodeInvalidRequest, "response_type must be code")
		return
	}
	if !authcode.ValidChallenge(challenge) {
		writeErr(w, http.StatusBadRequest, internal.CodeInvalidRequest, "missing or malformed code_challenge")
		return
	}

	if r.Method == http.MethodGet {
		renderLoginForm(w, clientID, redirectURI, challenge, state)
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, internal.CodeInvalidRequest, "use GET or POST")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeErr(w, http.StatusBadRequest, internal.CodeInvalidRequest, "bad form")
		return
	}
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	if !s.cfg.CheckUser(username, password) {
		http.Error(w, "login failed: invalid username or password", http.StatusUnauthorized)
		return
	}

	code, err := s.codes.Create(clientID, redirectURI, challenge, username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, internal.CodeKeyUnavailable, "could not issue code")
		return
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		writeErr(w, http.StatusBadRequest, internal.CodeInvalidRedirect, "bad redirect_uri")
		return
	}
	qq := u.Query()
	qq.Set("code", code)
	if state != "" {
		qq.Set("state", state)
	}
	u.RawQuery = qq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func renderLoginForm(w http.ResponseWriter, clientID, redirectURI, challenge, state string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	esc := html.EscapeString
	_, _ = fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>Local Login</title>
<style>body{font-family:system-ui;max-width:24rem;margin:4rem auto}input{width:100%%;padding:.5rem;margin:.3rem 0}button{padding:.6rem 1.2rem}</style>
</head><body><h2>本地身份认证服务</h2>
<form method="post" action="/authorize">
<input type="hidden" name="client_id" value="%s">
<input type="hidden" name="redirect_uri" value="%s">
<input type="hidden" name="code_challenge" value="%s">
<input type="hidden" name="state" value="%s">
<label>用户名 <input name="username" autocomplete="username"></label>
<label>密码 <input name="password" type="password" autocomplete="current-password"></label>
<button type="submit">登录并授权</button>
</form><p>默认演示账号：alice / password123</p></body></html>`,
		esc(clientID), esc(redirectURI), esc(challenge), esc(state))
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	JTI          string `json:"jti"`
	Subject      string `json:"subject"`
}

// handleToken 处理 authorization_code 与 refresh_token 两种 grant。
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, internal.CodeInvalidRequest, "POST only")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeErr(w, http.StatusBadRequest, internal.CodeInvalidRequest, "bad form")
		return
	}
	cl, ok := s.authenticateClient(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
		writeErr(w, http.StatusUnauthorized, internal.CodeUnauthorizedClient, "invalid client credentials")
		return
	}

	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, r, cl)
	case "refresh_token":
		s.rotateRefresh(w, r)
	default:
		writeErr(w, http.StatusBadRequest, internal.CodeInvalidRequest, "unsupported grant_type")
	}
}

func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request, cl config.Client) {
	codeValue := r.PostFormValue("code")
	redirectURI := r.PostFormValue("redirect_uri")
	verifier := r.PostFormValue("code_verifier")
	if codeValue == "" || redirectURI == "" || verifier == "" {
		writeErr(w, http.StatusBadRequest, internal.CodeInvalidRequest, "code, redirect_uri and code_verifier are required")
		return
	}
	c, err := s.codes.Exchange(codeValue, cl.ID, redirectURI, verifier)
	if err != nil {
		ec := internal.CodeOf(err)
		writeErr(w, http.StatusBadRequest, ec, err.Error())
		return
	}
	s.issueBundle(w, c.Subject, cl.ID, "")
}

func (s *Server) rotateRefresh(w http.ResponseWriter, r *http.Request) {
	old := r.PostFormValue("refresh_token")
	if old == "" {
		writeErr(w, http.StatusBadRequest, internal.CodeInvalidRequest, "refresh_token required")
		return
	}
	newRT, node, err := s.fresh.Rotate(old)
	if err != nil {
		ec := internal.CodeOf(err)
		writeErr(w, http.StatusBadRequest, ec, err.Error())
		return
	}
	s.issueBundle(w, node.Subject, node.ClientID, newRT, node.FamilyID)
}

// issueBundle 签发访问令牌；newRT 为空表示首次登录，需要创建刷新令牌链。
func (s *Server) issueBundle(w http.ResponseWriter, subject, clientID, newRT string, familyIDs ...string) {
	jti, err := store.RandomToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, internal.CodeKeyUnavailable, "internal error")
		return
	}
	access, _, err := s.tokens.Issue(subject, clientID, jti, s.cfg.AccessTokenTTL.Std())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, internal.CodeOf(err), "could not issue access token")
		return
	}

	family := ""
	if len(familyIDs) > 0 {
		family = familyIDs[0]
	}
	if newRT == "" {
		rt, node, err := s.fresh.Issue(subject, clientID, jti)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, internal.CodeKeyUnavailable, "internal error")
			return
		}
		newRT, family = rt, node.FamilyID
	}
	s.fresh.BindAccessJTI(family, jti)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.cfg.AccessTokenTTL.Std().Seconds()),
		RefreshToken: newRT,
		JTI:          jti,
		Subject:      subject,
	})
}

// handleVerify 校验访问令牌：Authorization: Bearer 或 Body {"token": ...}。
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	raw := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		raw = strings.TrimPrefix(h, "Bearer ")
	}
	if raw == "" {
		var body struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		raw = body.Token
	}
	if raw == "" {
		writeErr(w, http.StatusBadRequest, internal.CodeInvalidRequest, "token required")
		return
	}
	claims, err := s.tokens.Verify(raw)
	if err != nil {
		ec := internal.CodeOf(err)
		writeErr(w, http.StatusUnauthorized, ec, ecDescription(ec))
		return
	}
	if s.fresh.IsAccessRevoked(claims.JTI) {
		writeErr(w, http.StatusUnauthorized, internal.CodeTokenRevoked, "token has been revoked")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"active":    true,
		"subject":   claims.Subject,
		"client_id": claims.ClientID,
		"jti":       claims.JTI,
		"issuer":    claims.Issuer,
		"audience":  claims.Audience,
		"expires":   claims.Expires,
	})
}

// ecDescription 只返回稳定、通用的原因描述，不透传底层加解密错误。
func ecDescription(code internal.ErrorCode) string {
	switch code {
	case internal.CodeTokenExpired:
		return "token expired"
	case internal.CodeTokenIssuer:
		return "issuer mismatch"
	case internal.CodeTokenAudience:
		return "audience mismatch"
	case internal.CodeBadSignature:
		return "signature invalid or signing key rejected"
	case internal.CodeMalformedToken:
		return "malformed token"
	default:
		return "token rejected"
	}
}

// handleRevoke 撤销刷新令牌（连带整条链与链上所有访问令牌）。
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authenticateClient(r); !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
		writeErr(w, http.StatusUnauthorized, internal.CodeUnauthorizedClient, "invalid client credentials")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeErr(w, http.StatusBadRequest, internal.CodeInvalidRequest, "bad form")
		return
	}
	rt := r.PostFormValue("refresh_token")
	if rt == "" {
		writeErr(w, http.StatusBadRequest, internal.CodeInvalidRequest, "refresh_token required")
		return
	}
	if err := s.fresh.RevokeToken(rt); err != nil {
		writeErr(w, http.StatusBadRequest, internal.CodeOf(err), err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"revoked": true})
}

// handleLogout 按访问令牌登出：撤销其 jti 与所属刷新令牌链。
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	raw := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		raw = strings.TrimPrefix(h, "Bearer ")
	}
	if raw == "" {
		_ = r.ParseForm()
		raw = r.PostFormValue("token")
	}
	claims, err := s.tokens.Verify(raw)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, internal.CodeOf(err), "invalid token")
		return
	}
	s.fresh.RevokeAccessJTI(claims.JTI)
	// 找到该 jti 关联的刷新链并整链撤销。
	if family := s.familyOfJTI(claims.JTI); family != "" {
		s.fresh.RevokeFamily(family)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"logged_out": true})
}

func (s *Server) familyOfJTI(jti string) string {
	family := ""
	s.store.View(func(st *store.State) {
		for f, jtis := range st.FamilyJTIs {
			for _, j := range jtis {
				if j == jti {
					family = f
					return
				}
			}
		}
	})
	return family
}

// handleRotate 立即轮换签名密钥（本地手动运维入口）。
func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	k, err := s.store.NewKey(s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, internal.CodeKeyUnavailable, "rotate failed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"active_key_id": k.ID})
}

// handleAudit 返回安全审计记录（复用检测、撤销等）。
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	events := s.store.AuditEvents()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"events": events})
}
