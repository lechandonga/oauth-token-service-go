package authcode

import (
	"encoding/base64"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal/store"
)

const testClient = "local-cli"
const testRedirect = "http://127.0.0.1:9876/callback"

func testVerifier() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func scenario(t *testing.T, name string, fn func(t *testing.T)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Logf("SCENARIO %s: START", name)
		fn(t)
		t.Logf("SCENARIO %s: PASS", name)
	})
}

func issue(t *testing.T, m *Manager, verifier string) string {
	t.Helper()
	code, err := m.Issue(IssueParams{
		ClientID:    testClient,
		RedirectURI: testRedirect,
		Challenge:   S256Challenge(verifier),
		Subject:     "demo",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return code
}

func TestAuthorizationCodeScenarios(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	advance := func(d time.Duration) { now = now.Add(d) }

	newSvc := func(t *testing.T, ttl time.Duration) *Manager {
		f := store.NewJSONFile(filepath.Join(t.TempDir(), "codes.json"))
		m, err := NewManager(f, Config{TTL: ttl}, clock)
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		return m
	}

	scenario(t, "valid_exchange_with_pkce_s256", func(t *testing.T) {
		m := newSvc(t, time.Minute)
		verifier := testVerifier()
		code := issue(t, m, verifier)
		got, err := m.Exchange(ExchangeParams{Code: code, ClientID: testClient, RedirectURI: testRedirect, CodeVerifier: verifier})
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if got.Subject != "demo" || !got.Used {
			t.Fatalf("unexpected snapshot: %+v", got)
		}
		t.Logf("case valid exchange: consumed code subject=%q -> RESULT success", got.Subject)
	})

	scenario(t, "replay_rejected_once_only", func(t *testing.T) {
		m := newSvc(t, time.Minute)
		verifier := testVerifier()
		code := issue(t, m, verifier)

		if _, err := m.Exchange(ExchangeParams{Code: code, ClientID: testClient, RedirectURI: testRedirect, CodeVerifier: verifier}); err != nil {
			t.Fatalf("first exchange: %v", err)
		}
		_, err := m.Exchange(ExchangeParams{Code: code, ClientID: testClient, RedirectURI: testRedirect, CodeVerifier: verifier})
		if !errors.Is(err, ErrCodeAlreadyUsed) {
			t.Fatalf("expected ErrCodeAlreadyUsed, got %v", err)
		}
		t.Logf("case second presentation -> RESULT %q", ErrorCode(err))
	})

	scenario(t, "concurrent_exchange_single_winner", func(t *testing.T) {
		m := newSvc(t, time.Minute)
		verifier := testVerifier()
		code := issue(t, m, verifier)

		const n = 16
		var wg sync.WaitGroup
		var mu sync.Mutex
		success, replay := 0, 0
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := m.Exchange(ExchangeParams{Code: code, ClientID: testClient, RedirectURI: testRedirect, CodeVerifier: verifier})
				mu.Lock()
				switch {
				case err == nil:
					success++
				case errors.Is(err, ErrCodeAlreadyUsed):
					replay++
				default:
					t.Errorf("unexpected error: %v", err)
				}
				mu.Unlock()
			}()
		}
		close(start)
		wg.Wait()
		if success != 1 || replay != n-1 {
			t.Fatalf("expected exactly 1 success and %d replays, got success=%d replay=%d", n-1, success, replay)
		}
		t.Logf("case %d concurrent exchanges -> RESULT success=1 rejected=%d", n, replay)
	})

	scenario(t, "expired_code_rejected", func(t *testing.T) {
		m := newSvc(t, 2*time.Second)
		verifier := testVerifier()
		code := issue(t, m, verifier)
		advance(3 * time.Second)
		_, err := m.Exchange(ExchangeParams{Code: code, ClientID: testClient, RedirectURI: testRedirect, CodeVerifier: verifier})
		if !errors.Is(err, ErrCodeExpired) {
			t.Fatalf("expected ErrCodeExpired, got %v", err)
		}
		t.Logf("case exchange after TTL -> RESULT %q", ErrorCode(err))
	})

	scenario(t, "wrong_pkce_verifier_rejected", func(t *testing.T) {
		m := newSvc(t, time.Minute)
		verifier := testVerifier()
		code := issue(t, m, verifier)
		other := testVerifier() + "A"
		_, err := m.Exchange(ExchangeParams{Code: code, ClientID: testClient, RedirectURI: testRedirect, CodeVerifier: other})
		if !errors.Is(err, ErrPKCEMismatch) {
			t.Fatalf("expected ErrPKCEMismatch, got %v", err)
		}
		// consumed by failed presentation: retry with correct verifier also fails
		_, err = m.Exchange(ExchangeParams{Code: code, ClientID: testClient, RedirectURI: testRedirect, CodeVerifier: verifier})
		if !errors.Is(err, ErrCodeAlreadyUsed) {
			t.Fatalf("expected replay rejection after failed use, got %v", err)
		}
		t.Logf("case wrong verifier -> pkce_mismatch; retry correct verifier -> %q", ErrorCode(err))
	})

	scenario(t, "tampered_parameters_rejected", func(t *testing.T) {
		m := newSvc(t, time.Minute)
		code := issue(t, m, testVerifier())

		_, err := m.Exchange(ExchangeParams{Code: code, ClientID: "other-cli", RedirectURI: testRedirect, CodeVerifier: testVerifier()})
		if !errors.Is(err, ErrParameterMismatch) {
			t.Fatalf("client mismatch: expected ErrParameterMismatch, got %v", err)
		}
		// new code for redirect tamper case
		code = issue(t, m, testVerifier())
		_, err = m.Exchange(ExchangeParams{Code: code, ClientID: testClient, RedirectURI: "http://127.0.0.1:9876/evil", CodeVerifier: testVerifier()})
		if !errors.Is(err, ErrParameterMismatch) {
			t.Fatalf("redirect mismatch: expected ErrParameterMismatch, got %v", err)
		}
		t.Logf("case altered client_id and redirect_uri -> RESULT %q", ErrorCode(err))
	})

	scenario(t, "unknown_code_rejected", func(t *testing.T) {
		m := newSvc(t, time.Minute)
		_, err := m.Exchange(ExchangeParams{Code: "never-issued", ClientID: testClient, RedirectURI: testRedirect, CodeVerifier: testVerifier()})
		if !errors.Is(err, ErrCodeNotFound) {
			t.Fatalf("expected ErrCodeNotFound, got %v", err)
		}
		t.Logf("case unknown code -> RESULT %q", ErrorCode(err))
	})

	scenario(t, "client_and_redirect_registration_validation", func(t *testing.T) {
		clients := map[string][]string{testClient: {testRedirect}}
		cases := []struct {
			name     string
			client   string
			redirect string
			wantOK   bool
		}{
			{"registered pair", testClient, testRedirect, true},
			{"unknown client", "nope", testRedirect, false},
			{"unregistered redirect", testClient, "http://127.0.0.1:1/evil", false},
		}
		for _, tc := range cases {
			err := ValidateClientAndRedirect(clients, tc.client, tc.redirect)
			if (err == nil) != tc.wantOK {
				t.Fatalf("%s: err=%v wantOK=%v", tc.name, err, tc.wantOK)
			}
			t.Logf("case %q -> RESULT ok=%v", tc.name, err == nil)
		}
		bad := []string{
			"http://example.com/cb",      // non-loopback
			"ftp://127.0.0.1/x",          // bad scheme
			"http://127.0.0.1:9/cb?x=1",  // query
			"http://127.0.0.1:9/cb#frag", // fragment
			"://nohost",                  // malformed
		}
		for _, u := range bad {
			if err := ValidateRedirectURI(u); err == nil {
				t.Fatalf("expected redirect %q rejected", u)
			}
		}
		if err := ValidateChallenge("not-base64-url!!"); err == nil {
			t.Fatal("expected malformed challenge rejected")
		}
		if err := ValidateChallenge(S256Challenge(testVerifier())); err != nil {
			t.Fatalf("valid challenge rejected: %v", err)
		}
		t.Logf("case %d malformed redirects and bad challenge -> RESULT all rejected", len(bad))
	})

	scenario(t, "used_code_survives_restart", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "codes.json")
		f := store.NewJSONFile(dir)
		m1, err := NewManager(f, Config{TTL: time.Minute}, clock)
		if err != nil {
			t.Fatal(err)
		}
		verifier := testVerifier()
		code := issue(t, m1, verifier)
		if _, err := m1.Exchange(ExchangeParams{Code: code, ClientID: testClient, RedirectURI: testRedirect, CodeVerifier: verifier}); err != nil {
			t.Fatal(err)
		}

		m2, err := NewManager(store.NewJSONFile(dir), Config{TTL: time.Minute}, clock)
		if err != nil {
			t.Fatal(err)
		}
		_, err = m2.Exchange(ExchangeParams{Code: code, ClientID: testClient, RedirectURI: testRedirect, CodeVerifier: verifier})
		if !errors.Is(err, ErrCodeAlreadyUsed) {
			t.Fatalf("after restart expected replay rejection, got %v", err)
		}
		t.Logf("case replay against reloaded store -> RESULT %q", ErrorCode(err))
	})
}

// keep imports used
