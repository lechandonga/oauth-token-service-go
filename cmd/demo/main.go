// Command demo 在本机临时目录中用 httptest 启动完整服务，
// 手工走一遍：PKCE 登录、授权码兑换/重放、令牌校验、
// 刷新轮换/复用撤销、登出、密钥轮换宽限窗口与重启恢复。
// 运行：go run ./cmd/demo
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal"
	"github.com/lechandonga/oauth-token-service-go/internal/config"
	"github.com/lechandonga/oauth-token-service-go/internal/server"
	"github.com/lechandonga/oauth-token-service-go/internal/store"
	"github.com/lechandonga/oauth-token-service-go/internal/token"
)

var b64 = base64.RawURLEncoding

type env struct {
	base   string
	client *http.Client
}

func main() {
	tmp, err := os.MkdirTemp("", "oauth-demo-")
	must(err)
	defer os.RemoveAll(tmp)

	cfg := config.Default()
	cfg.DataFile = filepath.Join(tmp, "state.json")
	cfg.CodeTTL = config.Duration(2 * time.Minute)
	cfg.AccessTokenTTL = config.Duration(15 * time.Minute)
	cfg.RefreshTokenTTL = config.Duration(time.Hour)
	cfg.ClockSkewLeeway = config.Duration(60 * time.Second)
	cfg.KeyGraceWindow = config.Duration(time.Hour)

	st, err := store.New(cfg.DataFile)
	must(err)

	ts := startServer(cfg, st)
	defer ts.Close()
	e := &env{base: ts.URL, client: newClient()}

	fmt.Println("== 本地 OAuth 全流程演示 ==")
	fmt.Println("服务地址:", ts.URL)
	fmt.Println("数据文件:", cfg.DataFile)

	verifier := randomVerifier()
	challenge := pkceChallenge(verifier)

	s := check("GET /authorize 返回登录表单")
	resp, _ := e.get(e.base + authorizeQuery(challenge))
	body := readAll(resp)
	s.expect(resp.StatusCode == 200 && strings.Contains(string(body), "登录并授权"),
		"status=%d", resp.StatusCode)

	s = check("错误密码被拒绝")
	resp = e.login(challenge, "alice", "wrong")
	drain(resp)
	s.expect(resp.StatusCode == 401, "status=%d", resp.StatusCode)

	s = check("未注册 redirect_uri 不下发授权码")
	evilForm := url.Values{
		"response_type":  {"code"},
		"client_id":      {"local-cli"},
		"redirect_uri":   {"http://evil.example/cb"},
		"code_challenge": {challenge},
		"state":          {"xyz"},
	}
	req, _ := http.NewRequest(http.MethodGet, e.base+"/authorize?"+evilForm.Encode(), nil)
	resp, err = e.client.Do(req)
	must(err)
	evilCode := jsonCode(readAll(resp))
	drain(resp)
	s.expect(resp.StatusCode == 400 && evilCode == string(internal.CodeInvalidRedirect),
		"status=%d code=%s", resp.StatusCode, errorCode(resp))

	s = check("正确登录后 302 回调并附带授权码")
	resp = e.login(challenge, "alice", "password123")
	loc := resp.Header.Get("Location")
	drain(resp)
	u, _ := url.Parse(loc)
	code := u.Query().Get("code")
	s.expect(resp.StatusCode == 302 && code != "", "status=%d location=%s", resp.StatusCode, loc)

	s = check("PKCE verifier 不匹配被拒绝")
	_, err = e.tokenExchange(code, randomVerifier())
	s.expect(errorCodeStr(err) == string(internal.CodePKCEMismatch), "err=%v", err)

	s = check("授权码正确兑换出访问/刷新令牌")
	tok, err := e.tokenExchange(code, verifier)
	must(err)
	s.expect(tok.AccessToken != "" && tok.RefreshToken != "", "tokens empty")

	s = check("访问令牌校验通过")
	claims := e.verify(tok.AccessToken)
	s.expect(claims["active"] == true && claims["subject"] == "alice", "claims=%v", claims)

	s = check("授权码重放被拒绝（一次性）")
	_, err = e.tokenExchange(code, verifier)
	s.expect(errorCodeStr(err) == string(internal.CodeInvalidGrant), "err=%v", err)

	s = check("签名被篡改返回 bad_signature")
	resp = e.verifyRaw(tamper(tok.AccessToken))
	s.expect(resp.StatusCode == 401 && errorCode(resp) == string(internal.CodeBadSignature),
		"status=%d", resp.StatusCode)

	s = check("刷新令牌轮换：旧换新成功")
	refreshed, err := e.refresh(tok.RefreshToken)
	must(err)
	s.expect(refreshed.RefreshToken != tok.RefreshToken, "same refresh token returned")

	s = check("旧刷新令牌复用触发整链撤销并留痕")
	_, err = e.refresh(tok.RefreshToken)
	s.expect(errorCodeStr(err) == string(internal.CodeReuseDetected), "err=%v", err)
	_, err = e.refresh(refreshed.RefreshToken)
	s.expect(errorCodeStr(err) == string(internal.CodeInvalidGrant), "new token still usable: %v", err)

	s = check("/audit 可见复用事件")
	s.expect(strings.Contains(e.audit(), "refresh_reuse_detected"), "no reuse event in audit log")

	verifier2 := randomVerifier()
	code2 := e.loginAndGetCode(pkceChallenge(verifier2))
	tok2, err := e.tokenExchange(code2, verifier2)
	must(err)
	s = check("登出后访问令牌与刷新令牌立即失效")
	s.expect(e.verify(tok2.AccessToken)["active"] == true, "pre-logout verify failed")
	resp = e.logout(tok2.AccessToken)
	drain(resp)
	resp = e.verifyRaw(tok2.AccessToken)
	s.expect(resp.StatusCode == 401 && errorCode(resp) == string(internal.CodeTokenRevoked),
		"status=%d code=%s", resp.StatusCode, errorCode(resp))
	_, err = e.refresh(tok2.RefreshToken)
	s.expect(errorCodeStr(err) == string(internal.CodeInvalidGrant), "refresh after logout: %v", err)

	s = check("进程重启后撤销状态不复活")
	st2, err := store.New(cfg.DataFile)
	must(err)
	ts2 := startServer(cfg, st2)
	defer ts2.Close()
	e2 := &env{base: ts2.URL, client: newClient()}
	resp = e2.verifyRaw(tok2.AccessToken)
	s.expect(resp.StatusCode == 401, "revived token after restart: status=%d", resp.StatusCode)

	s = check("轻微时钟偏差不误杀（leeway=60s）")
	jti, _ := store.RandomToken()
	clockMgr := token.NewManager(st2, cfg.Issuer, cfg.Audience,
		cfg.KeyGraceWindow.Std(), cfg.ClockSkewLeeway.Std(), time.Now)
	access, _, err := clockMgr.Issue("alice", "local-cli", jti, 30*time.Second)
	must(err)
	slowMgr := token.NewManager(st2, cfg.Issuer, cfg.Audience,
		cfg.KeyGraceWindow.Std(), cfg.ClockSkewLeeway.Std(), func() time.Time { return time.Now().Add(-30 * time.Second) })
	_, err = slowMgr.Verify(access)
	s.expect(err == nil, "skewed clock rejected token: %v", err)

	s = check("密钥轮换：宽限窗口内旧令牌可用，超窗失效")
	jti2, _ := store.RandomToken()
	oldAccess, _, err := clockMgr.Issue("alice", "local-cli", jti2, 30*time.Minute)
	must(err)
	_, err = st2.NewKey(time.Now())
	must(err)
	graceMgr := token.NewManager(st2, cfg.Issuer, cfg.Audience, time.Hour, 0, time.Now)
	_, err = graceMgr.Verify(oldAccess)
	s.expect(err == nil, "old token rejected within grace: %v", err)
	noGraceMgr := token.NewManager(st2, cfg.Issuer, cfg.Audience, 0, 0, time.Now)
	_, err = noGraceMgr.Verify(oldAccess)
	s.expect(internal.CodeOf(err) == internal.CodeBadSignature, "expected key rejected past grace, got %v", err)

	s = check("过期令牌返回 token_expired")
	futureMgr := token.NewManager(st2, cfg.Issuer, cfg.Audience, 2*time.Hour, 0,
		func() time.Time { return time.Now().Add(time.Hour) })
	_, err = futureMgr.Verify(oldAccess)
	s.expect(internal.CodeOf(err) == internal.CodeTokenExpired, "got %v", err)

	fmt.Println()
	if failures > 0 {
		fmt.Printf("演示结束：%d 个场景失败\n", failures)
		os.Exit(1)
	}
	fmt.Printf("演示结束：全部 %d 个场景通过\n", passed)
}

var passed, failures int

type step struct{ name string }

func check(name string) step {
	fmt.Printf("[场景] %-42s ", name)
	return step{name: name}
}

func (s step) expect(ok bool, format string, args ...any) {
	if ok {
		passed++
		fmt.Println("PASS")
		return
	}
	failures++
	fmt.Printf("FAIL (%s)\n", fmt.Sprintf(format, args...))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type apiError struct{ code string }

func (e *apiError) Error() string { return e.code }

func errorCodeStr(err error) string {
	var ae *apiError
	if err != nil {
		if e, ok := err.(*apiError); ok {
			ae = e
		}
	}
	if ae != nil {
		return ae.code
	}
	return ""
}

type tokenResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	JTI          string `json:"jti"`
}

func startServer(cfg config.Config, st *store.Store) *httptest.Server {
	return httptest.NewServer(server.New(cfg, st, time.Now).Routes())
}

func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func authorizeQuery(challenge string) string {
	return "/authorize?response_type=code&client_id=local-cli" +
		"&redirect_uri=" + url.QueryEscape("http://127.0.0.1:9999/callback") +
		"&code_challenge=" + challenge + "&state=xyz"
}

func (e *env) get(rawurl string) (*http.Response, error) {
	return e.client.Get(rawurl)
}

func (e *env) login(challenge, username, password string) *http.Response {
	form := url.Values{
		"response_type":  {"code"},
		"client_id":      {"local-cli"},
		"redirect_uri":   {"http://127.0.0.1:9999/callback"},
		"code_challenge": {challenge},
		"state":          {"xyz"},
		"username":       {username},
		"password":       {password},
	}
	resp, err := e.client.PostForm(e.base+"/authorize", form)
	must(err)
	return resp
}

func (e *env) loginAndGetCode(challenge string) string {
	resp := e.login(challenge, "alice", "password123")
	loc := resp.Header.Get("Location")
	drain(resp)
	u, _ := url.Parse(loc)
	return u.Query().Get("code")
}

func (e *env) postForm(path string, form url.Values) ([]byte, *http.Response, error) {
	req, _ := http.NewRequest(http.MethodPost, e.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("local-cli", "local-secret")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	data := readAll(resp)
	if resp.StatusCode != 200 {
		return nil, resp, &apiError{code: jsonCode(data)}
	}
	return data, resp, nil
}

func (e *env) tokenExchange(codeValue, verifier string) (tokenResult, error) {
	var out tokenResult
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {codeValue},
		"redirect_uri":  {"http://127.0.0.1:9999/callback"},
		"code_verifier": {verifier},
	}
	data, _, err := e.postForm("/token", form)
	if err != nil {
		return out, err
	}
	must(json.Unmarshal(data, &out))
	return out, nil
}

func (e *env) refresh(rt string) (tokenResult, error) {
	var out tokenResult
	data, _, err := e.postForm("/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rt},
	})
	if err != nil {
		return out, err
	}
	must(json.Unmarshal(data, &out))
	return out, nil
}

func (e *env) verifyRaw(tok string) *http.Response {
	body := `{"token":` + strconv.Quote(tok) + `}`
	req, _ := http.NewRequest(http.MethodPost, e.base+"/verify", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	must(err)
	return resp
}

func (e *env) verify(tok string) map[string]any {
	resp := e.verifyRaw(tok)
	data := readAll(resp)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return out
}

func (e *env) logout(tok string) *http.Response {
	req, _ := http.NewRequest(http.MethodPost, e.base+"/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := e.client.Do(req)
	must(err)
	return resp
}

func (e *env) audit() string {
	resp, err := e.get(e.base + "/audit")
	must(err)
	return string(readAll(resp))
}

func readAll(resp *http.Response) []byte {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func errorCode(resp *http.Response) string {
	body := readAll(resp)
	return jsonCode(body)
}

func jsonCode(data []byte) string {
	var v struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(data, &v)
	return v.Error
}

func randomVerifier() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b64.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64.EncodeToString(sum[:])
}

func tamper(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return tok
	}
	c := byte('A')
	if parts[2][0] == 'A' {
		c = 'B'
	}
	parts[2] = string(c) + parts[2][1:]
	return strings.Join(parts, ".")
}
