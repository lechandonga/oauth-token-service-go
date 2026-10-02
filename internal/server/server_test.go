package server_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal/config"
	"github.com/lechandonga/oauth-token-service-go/internal/server"
	"github.com/lechandonga/oauth-token-service-go/internal/store"
)

var b64 = base64.RawURLEncoding

type testEnv struct {
	t   *testing.T
	cfg config.Config
	ts  *httptest.Server
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	cfg := config.Default()
	cfg.DataFile = filepath.Join(t.TempDir(), "state.json")
	cfg.CodeTTL = config.Duration(time.Minute)
	st, err := store.New(cfg.DataFile)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(server.New(cfg, st, time.Now).Routes())
	t.Cleanup(ts.Close)
	return &testEnv{t: t, cfg: cfg, ts: ts}
}

func (e *testEnv) client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func (e *testEnv) loginCode(challenge string) string {
	form := url.Values{
		"response_type":  {"code"},
		"client_id":      {"local-cli"},
		"redirect_uri":   {"http://127.0.0.1:9999/callback"},
		"code_challenge": {challenge},
		"state":          {"xyz"},
		"username":       {"alice"},
		"password":       {"password123"},
	}
	resp, err := e.client().PostForm(e.ts.URL+"/authorize", form)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	u, _ := url.Parse(resp.Header.Get("Location"))
	return u.Query().Get("code")
}

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (e *testEnv) exchange(code, verifier string) (tokenResp, *http.Response) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:9999/callback"},
		"code_verifier": {verifier},
	}
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("local-cli", "local-secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	var out tokenResp
	data, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &out)
	return out, resp
}

func pkcePair() (verifier, challenge string) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	verifier = b64.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	challenge = b64.EncodeToString(sum[:])
	return
}

func errCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	var v struct {
		Error string `json:"error"`
	}
	data, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &v)
	return v.Error
}

func TestHTTPClientValidation(t *testing.T) {
	e := newEnv(t)

	t.Run("未知 client_id", func(t *testing.T) {
		q := url.Values{
			"response_type":  {"code"},
			"client_id":      {"unknown"},
			"redirect_uri":   {"http://127.0.0.1:9999/callback"},
			"code_challenge": {strings.Repeat("a", 43)},
		}
		resp, err := http.Get(e.ts.URL + "/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if code := errCode(t, resp); resp.StatusCode != 400 || code != "unauthorized_client" {
			t.Fatalf("status=%d code=%s", resp.StatusCode, code)
		}
		t.Logf("[场景] %-14s 用例=%-22s 结果=PASS", "客户端校验", "未知 client_id")
	})

	t.Run("错误 client 密钥", func(t *testing.T) {
		verifier, challenge := pkcePair()
		code := e.loginCode(challenge)
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {"http://127.0.0.1:9999/callback"},
			"code_verifier": {verifier},
		}
		req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("local-cli", "bad-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if code := errCode(t, resp); resp.StatusCode != 401 || code != "unauthorized_client" {
			t.Fatalf("status=%d code=%s", resp.StatusCode, code)
		}
		t.Logf("[场景] %-14s 用例=%-22s 结果=PASS", "客户端校验", "错误 client_secret")
	})
}

func TestHTTPConcurrentCodeExchange(t *testing.T) {
	e := newEnv(t)
	verifier, challenge := pkcePair()
	code := e.loginCode(challenge)

	const n = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	success, failed := 0, 0
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, resp := e.exchange(code, verifier)
			defer resp.Body.Close()
			mu.Lock()
			defer mu.Unlock()
			if resp.StatusCode == 200 {
				success++
			} else {
				failed++
			}
		}()
	}
	close(start)
	wg.Wait()
	if success != 1 || failed != n-1 {
		t.Fatalf("成功=%d 失败=%d，要求恰好 1 个成功", success, failed)
	}
	t.Logf("[场景] %-14s 用例=%-22s 结果=PASS (成功=1 失败=%d)", "并发兑换", "20 个并发 HTTP 兑换", n-1)
}

func TestHTTPFullFlowAndRevoke(t *testing.T) {
	e := newEnv(t)
	verifier, challenge := pkcePair()
	code := e.loginCode(challenge)
	tok, resp := e.exchange(code, verifier)
	resp.Body.Close()
	if tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatal("兑换未返回令牌")
	}
	t.Logf("[场景] %-14s 用例=%-22s 结果=PASS", "完整流程", "登录+兑换")

	// 校验
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/verify",
		strings.NewReader(`{"token":`+jsonString(tok.AccessToken)+`}`))
	req.Header.Set("Content-Type", "application/json")
	vr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if vr.StatusCode != 200 {
		t.Fatalf("verify status=%d", vr.StatusCode)
	}
	vr.Body.Close()
	t.Logf("[场景] %-14s 用例=%-22s 结果=PASS", "完整流程", "令牌校验")

	// 登出后校验返回 token_revoked
	lr, err := http.NewRequest(http.MethodPost, e.ts.URL+"/logout", nil)
	if err != nil {
		t.Fatal(err)
	}
	lr.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	lresp, err := http.DefaultClient.Do(lr)
	if err != nil {
		t.Fatal(err)
	}
	lresp.Body.Close()

	req2, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/verify",
		strings.NewReader(`{"token":`+jsonString(tok.AccessToken)+`}`))
	req2.Header.Set("Content-Type", "application/json")
	vr2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer vr2.Body.Close()
	if code := errCode(t, vr2); vr2.StatusCode != 401 || code != "token_revoked" {
		t.Fatalf("登出后 status=%d code=%s", vr2.StatusCode, code)
	}
	t.Logf("[场景] %-14s 用例=%-22s 结果=PASS", "完整流程", "登出后立即失效")

	// 重启：重新打开同一数据文件，撤销状态保留
	st2, err := store.New(e.cfg.DataFile)
	if err != nil {
		t.Fatal(err)
	}
	ts2 := httptest.NewServer(server.New(e.cfg, st2, time.Now).Routes())
	defer ts2.Close()
	req3, _ := http.NewRequest(http.MethodPost, ts2.URL+"/verify",
		strings.NewReader(`{"token":`+jsonString(tok.AccessToken)+`}`))
	req3.Header.Set("Content-Type", "application/json")
	vr3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer vr3.Body.Close()
	if vr3.StatusCode != 401 {
		t.Fatalf("重启后被撤销令牌复活: status=%d", vr3.StatusCode)
	}
	t.Logf("[场景] %-14s 用例=%-22s 结果=PASS", "重启恢复", "撤销状态持久化")
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
