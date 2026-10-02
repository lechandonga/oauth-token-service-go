package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	svcClient = "local-cli"
	svcRedir  = "http://127.0.0.1:9876/callback"
)

func oscenario(t *testing.T, name string, fn func(t *testing.T)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Logf("SCENARIO %s: START", name)
		fn(t)
		t.Logf("SCENARIO %s: PASS", name)
	})
}

func verifier() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i*3 + 11)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func challenge(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newTestService(t *testing.T, clock func() time.Time) *Service {
	t.Helper()
	cfg := Config{
		DataDir: filepath.Join(t.TempDir(), "data"),
		Issuer:  "test-issuer", Audience: "test-api",
		AccessTTL: time.Minute, CodeTTL: time.Minute, RefreshTTL: time.Hour,
		Leeway:  30 * time.Second,
		Clients: map[string][]string{svcClient: {svcRedir}},
		Users:   map[string]string{"demo": "pw"},
	}
	if clock != nil {
		cfg.Clock = clock
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func (s *Service) loginAndCode(t *testing.T, v string) string {
	t.Helper()
	code, err := s.Authorize(AuthorizeInput{
		ResponseType: "code", ClientID: svcClient, RedirectURI: svcRedir,
		Challenge: challenge(v), Username: "demo", Password: "pw",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	return code
}

func (s *Service) exchange(t *testing.T, code, v string) *TokenBundle {
	t.Helper()
	b, err := s.Token(ExchangeInput{
		GrantType: "authorization_code", Code: code, RedirectURI: svcRedir,
		ClientID: svcClient, CodeVerifier: v,
	})
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	return b
}

func svcErrCode(err error) string {
	var se *ServiceError
	if errors.As(err, &se) {
		return se.Code
	}
	return err.Error()
}

func TestServiceScenarios(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }

	oscenario(t, "full_code_pkce_token_introspect_flow", func(t *testing.T) {
		s := newTestService(t, clock)
		v := verifier()
		code := s.loginAndCode(t, v)
		bundle := s.exchange(t, code, v)
		res, err := s.Verify(bundle.AccessToken)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if res.Subject != "demo" {
			t.Fatalf("subject = %q", res.Subject)
		}
		t.Logf("case authorize->exchange->verify -> RESULT active sub=%q sid=%s", res.Subject, res.Session[:6])
	})

	oscenario(t, "authorization_failures_are_distinguishable", func(t *testing.T) {
		s := newTestService(t, clock)
		v := verifier()
		cases := []struct {
			name string
			in   AuthorizeInput
			want string
		}{
			{"bad credentials", AuthorizeInput{ResponseType: "code", ClientID: svcClient, RedirectURI: svcRedir, Challenge: challenge(v), Username: "demo", Password: "WRONG"}, "access_denied"},
			{"unknown client", AuthorizeInput{ResponseType: "code", ClientID: "ghost", RedirectURI: svcRedir, Challenge: challenge(v), Username: "demo", Password: "pw"}, "invalid_client"},
			{"unregistered redirect", AuthorizeInput{ResponseType: "code", ClientID: svcClient, RedirectURI: "http://127.0.0.1:9/evil", Challenge: challenge(v), Username: "demo", Password: "pw"}, "invalid_redirect_uri"},
			{"missing challenge", AuthorizeInput{ResponseType: "code", ClientID: svcClient, RedirectURI: svcRedir, Username: "demo", Password: "pw"}, "invalid_request"},
			{"bad response type", AuthorizeInput{ResponseType: "token", ClientID: svcClient, RedirectURI: svcRedir, Challenge: challenge(v), Username: "demo", Password: "pw"}, "unsupported_response_type"},
		}
		for _, tc := range cases {
			_, err := s.Authorize(tc.in)
			if got := svcErrCode(err); got != tc.want {
				t.Fatalf("%s: got %q want %q", tc.name, got, tc.want)
			}
			t.Logf("case %s -> RESULT %q", tc.name, tc.want)
		}
	})

	oscenario(t, "code_replay_and_pkce_failure_codes", func(t *testing.T) {
		s := newTestService(t, clock)
		v := verifier()
		code := s.loginAndCode(t, v)
		s.exchange(t, code, v)

		_, err := s.Token(ExchangeInput{GrantType: "authorization_code", Code: code, RedirectURI: svcRedir, ClientID: svcClient, CodeVerifier: v})
		if got := svcErrCode(err); got != "code_replayed" {
			t.Fatalf("replay: got %q", got)
		}
		t.Logf("case code replay -> RESULT code_replayed")

		code2 := s.loginAndCode(t, v)
		_, err = s.Token(ExchangeInput{GrantType: "authorization_code", Code: code2, RedirectURI: svcRedir, ClientID: svcClient, CodeVerifier: verifier() + "xx"})
		if got := svcErrCode(err); got != "pkce_mismatch" {
			t.Fatalf("pkce: got %q", got)
		}
		t.Logf("case wrong verifier -> RESULT pkce_mismatch")
	})

	oscenario(t, "clock_skew_tolerated_at_service_layer", func(t *testing.T) {
		tm := now
		s := newTestService(t, func() time.Time { return tm })
		bundle := s.exchange(t, s.loginAndCode(t, verifier()), verifier())

		tm = tm.Add(20 * time.Second)
		if _, err := s.Verify(bundle.AccessToken); err != nil {
			t.Fatalf("20s skew within 30s leeway: %v", err)
		}
		t.Logf("case +20s skew -> RESULT accepted")

		tm = tm.Add(30 * time.Second) // 50s total beyond iat, token exp = 60s though still valid
		_, err := s.Verify(bundle.AccessToken)
		if err != nil {
			t.Fatalf("50s skew, exp 60s: %v", err)
		}
		t.Logf("case +50s skew while unexpired -> RESULT accepted")
	})

	oscenario(t, "refresh_rotation_reuse_revokes_and_kills_access_token", func(t *testing.T) {
		s := newTestService(t, clock)
		bundle := s.exchange(t, s.loginAndCode(t, verifier()), verifier())
		oldRT := bundle.RefreshToken
		access := bundle.AccessToken

		rotated, err := s.Token(ExchangeInput{GrantType: "refresh_token", RefreshToken: oldRT})
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		t.Logf("case first refresh -> RESULT new tokens")

		_, err = s.Token(ExchangeInput{GrantType: "refresh_token", RefreshToken: oldRT})
		if got := svcErrCode(err); got != "invalid_grant" {
			t.Fatalf("reused refresh: got %q", got)
		}
		t.Logf("case reuse old refresh -> RESULT invalid_grant, family revoked")

		if _, err := s.Verify(access); err == nil {
			t.Fatal("access token of revoked family must be rejected")
		} else {
			t.Logf("case access token after family revoke -> RESULT %q", svcErrCode(err))
		}
		_, err = s.Token(ExchangeInput{GrantType: "refresh_token", RefreshToken: rotated.RefreshToken})
		if err == nil {
			t.Fatal("successor refresh must also be dead")
		}
		t.Logf("case successor refresh -> RESULT %q", svcErrCode(err))
	})

	oscenario(t, "logout_revokes_access_and_refresh_immediately", func(t *testing.T) {
		s := newTestService(t, clock)
		bundle := s.exchange(t, s.loginAndCode(t, verifier()), verifier())
		if err := s.Logout(bundle.SessionID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Verify(bundle.AccessToken); err == nil {
			t.Fatal("access token valid after logout")
		}
		if _, err := s.Token(ExchangeInput{GrantType: "refresh_token", RefreshToken: bundle.RefreshToken}); err == nil {
			t.Fatal("refresh token valid after logout")
		}
		t.Logf("case logout -> RESULT both access and refresh rejected")
	})

	oscenario(t, "revoked_and_rotated_state_survives_restart", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "data")
		cfg := Config{DataDir: dir, Issuer: "test-issuer", Audience: "test-api",
			Clients: map[string][]string{svcClient: {svcRedir}}, Users: map[string]string{"demo": "pw"}}
		s1, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		v := verifier()
		code := s1.loginAndCode(t, v)
		b1 := s1.exchange(t, code, v)
		rot, err := s1.Token(ExchangeInput{GrantType: "refresh_token", RefreshToken: b1.RefreshToken})
		if err != nil {
			t.Fatal(err)
		}
		if err := s1.Logout(b1.SessionID); err != nil {
			t.Fatal(err)
		}

		s2, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s2.Verify(b1.AccessToken); err == nil {
			t.Fatal("access token resurrected after restart")
		}
		if _, err := s2.Token(ExchangeInput{GrantType: "refresh_token", RefreshToken: rot.RefreshToken}); err == nil {
			t.Fatal("refresh token resurrected after restart")
		}
		t.Logf("case restart after logout -> RESULT tokens stay dead")
	})

	oscenario(t, "concurrent_http_code_exchange_single_winner", func(t *testing.T) {
		s := newTestService(t, clock)
		v := verifier()
		code := s.loginAndCode(t, v)
		ts := httptest.NewServer(s.Handler())
		defer ts.Close()

		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", code)
		form.Set("redirect_uri", svcRedir)
		form.Set("client_id", svcClient)
		form.Set("code_verifier", v)

		const n = 12
		var wg sync.WaitGroup
		var mu sync.Mutex
		success, replay := 0, 0
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				resp, err := http.Post(ts.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
				if err != nil {
					t.Error(err)
					return
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				mu.Lock()
				if resp.StatusCode == 200 {
					success++
				} else if strings.Contains(string(body), "code_replayed") {
					replay++
				} else {
					t.Errorf("unexpected status %d body=%s", resp.StatusCode, body)
				}
				mu.Unlock()
			}()
		}
		close(start)
		wg.Wait()
		if success != 1 || replay != n-1 {
			t.Fatalf("success=%d replay=%d", success, replay)
		}
		t.Logf("case %d concurrent HTTP exchanges -> RESULT 200=1 code_replayed=%d", n, replay)
	})

	oscenario(t, "http_login_form_and_authorize_redirect", func(t *testing.T) {
		s := newTestService(t, clock)
		ts := httptest.NewServer(s.Handler())
		defer ts.Close()

		v := verifier()
		q := url.Values{}
		q.Set("response_type", "code")
		q.Set("client_id", svcClient)
		q.Set("redirect_uri", svcRedir)
		q.Set("state", "abc123")
		q.Set("code_challenge", challenge(v))
		resp, err := http.Get(ts.URL + "/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), "Local sign-in") {
			t.Fatalf("login form status=%d", resp.StatusCode)
		}

		form := url.Values{}
		form.Set("response_type", "code")
		form.Set("client_id", svcClient)
		form.Set("redirect_uri", svcRedir)
		form.Set("state", "abc123")
		form.Set("code_challenge", challenge(v))
		form.Set("code_challenge_method", "S256")
		form.Set("username", "demo")
		form.Set("password", "pw")
		client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
		resp2, err := client.Post(ts.URL+"/authorize", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusSeeOther {
			t.Fatalf("authorize status = %d", resp2.StatusCode)
		}
		loc, err := resp2.Location()
		if err != nil {
			t.Fatal(err)
		}
		if loc.Query().Get("state") != "abc123" || loc.Query().Get("code") == "" {
			t.Fatalf("bad redirect location: %s", loc)
		}
		t.Logf("case login form -> POST /authorize -> RESULT 303 to %s with code+state", loc.Path)
	})
}
