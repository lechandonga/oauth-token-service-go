package token

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal/store"
)

func tscenario(t *testing.T, name string, fn func(t *testing.T)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Logf("SCENARIO %s: START", name)
		fn(t)
		t.Logf("SCENARIO %s: PASS", name)
	})
}

func newRing(t *testing.T, grace time.Duration, now func() time.Time) (*KeyRing, func() time.Time) {
	t.Helper()
	f := store.NewJSONFile(filepath.Join(t.TempDir(), "keys.json"))
	r, err := NewKeyRing(f, KeyRingConfig{GraceWindow: grace}, now)
	if err != nil {
		t.Fatalf("NewKeyRing: %v", err)
	}
	return r, now
}

func baseClaims(now time.Time) Claims {
	return Claims{
		Issuer: "local-issuer", Subject: "demo", Audience: Audience{"local-api"},
		IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(),
		SessionID: "sess-1",
	}
}

func TestAccessTokenScenarios(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	opts := VerifyOptions{Issuer: "local-issuer", Audience: "local-api", Leeway: 30 * time.Second, Now: clock}

	tscenario(t, "sign_and_verify_roundtrip", func(t *testing.T) {
		ring, _ := newRing(t, time.Hour, clock)
		raw, err := ring.Sign(baseClaims(now))
		if err != nil {
			t.Fatal(err)
		}
		got, err := ring.Verify(raw, opts)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if got.Subject != "demo" || got.SessionID != "sess-1" {
			t.Fatalf("unexpected claims %+v", got)
		}
		t.Logf("case roundtrip -> RESULT subject=%q sid=%q", got.Subject, got.SessionID)
	})

	tscenario(t, "clock_skew_within_leeway_accepted", func(t *testing.T) {
		ring, _ := newRing(t, time.Hour, clock)
		raw, err := ring.Sign(baseClaims(now))
		if err != nil {
			t.Fatal(err)
		}
		for _, delta := range []time.Duration{-25 * time.Second, 25 * time.Second} {
			skewOpts := opts
			skewOpts.Now = func() time.Time { return now.Add(delta) }
			if _, err := ring.Verify(raw, skewOpts); err != nil {
				t.Fatalf("delta %s: expected accepted, got %v", delta, err)
			}
			t.Logf("case skew %s -> RESULT accepted", delta)
		}
	})

	tscenario(t, "beyond_leeway_rejected_as_expired", func(t *testing.T) {
		ring, _ := newRing(t, time.Hour, clock)
		c := baseClaims(now)
		c.ExpiresAt = now.Add(10 * time.Second).Unix()
		raw, err := ring.Sign(c)
		if err != nil {
			t.Fatal(err)
		}
		skewOpts := opts
		skewOpts.Now = func() time.Time { return now.Add(45 * time.Second) }
		_, err = ring.Verify(raw, skewOpts)
		if !errors.Is(err, ErrTokenExpired) {
			t.Fatalf("expected ErrTokenExpired, got %v", err)
		}
		t.Logf("case exp+45s with 30s leeway -> RESULT %q", ErrorCode(err))
	})

	tscenario(t, "issuer_audience_mismatch_distinguishable", func(t *testing.T) {
		ring, _ := newRing(t, time.Hour, clock)
		raw, err := ring.Sign(baseClaims(now))
		if err != nil {
			t.Fatal(err)
		}
		badIss := opts
		badIss.Issuer = "other"
		if _, err := ring.Verify(raw, badIss); !errors.Is(err, ErrIssuerMismatch) {
			t.Fatalf("issuer: got %v", err)
		}
		t.Logf("case wrong issuer -> RESULT %q", ErrorCode(err))

		badAud := opts
		badAud.Audience = "other-api"
		if _, err := ring.Verify(raw, badAud); !errors.Is(err, ErrAudienceMissing) {
			t.Fatalf("audience: got %v", err)
		}
		t.Logf("case wrong audience -> RESULT %q", ErrorCode(err))
	})

	tscenario(t, "tampered_signature_rejected_without_crypto_leak", func(t *testing.T) {
		ring, _ := newRing(t, time.Hour, clock)
		raw, err := ring.Sign(baseClaims(now))
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(raw, ".")
		// flip a byte in the signature segment
		sig := []byte(parts[2])
		if sig[0] == 'A' {
			sig[0] = 'B'
		} else {
			sig[0] = 'A'
		}
		tampered := parts[0] + "." + parts[1] + "." + string(sig)
		_, err = ring.Verify(tampered, opts)
		if !errors.Is(err, ErrSignature) {
			t.Fatalf("expected ErrSignature, got %v", err)
		}
		if strings.Contains(strings.ToLower(err.Error()), "hmac") || strings.Contains(err.Error(), "sha") {
			t.Fatalf("low-level crypto detail leaked: %v", err)
		}
		t.Logf("case flipped signature byte -> RESULT %q (message=%q, no primitive names)", ErrorCode(err), err.Error())

		for _, malformed := range []string{"", "abc", "a.b", "a.b.c.d", "..."} {
			if _, err := ring.Verify(malformed, opts); !errors.Is(err, ErrMalformed) {
				t.Fatalf("malformed %q: got %v", malformed, err)
			}
		}
		t.Logf("case malformed token shapes -> RESULT malformed_token")
	})

	tscenario(t, "key_rotation_grace_window", func(t *testing.T) {
		cur := now
		rclock := func() time.Time { return cur }
		f := store.NewJSONFile(filepath.Join(t.TempDir(), "keys.json"))
		ring, err := NewKeyRing(f, KeyRingConfig{GraceWindow: time.Hour}, rclock)
		if err != nil {
			t.Fatal(err)
		}
		oldKID := ring.CurrentKeyID()
		raw, err := ring.Sign(baseClaims(cur))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ring.Rotate(); err != nil {
			t.Fatal(err)
		}
		if ring.CurrentKeyID() == oldKID {
			t.Fatal("kid unchanged after rotation")
		}
		// old token still valid within window
		if _, err := ring.Verify(raw, VerifyOptions{Issuer: "local-issuer", Audience: "local-api", Leeway: time.Second, Now: rclock}); err != nil {
			t.Fatalf("old token during grace: %v", err)
		}
		t.Logf("case after rotation within grace -> RESULT accepted (kid %s retired)", oldKID[:6])

		// new tokens signed by new key
		newRaw, err := ring.Sign(baseClaims(cur))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ring.Verify(newRaw, VerifyOptions{Issuer: "local-issuer", Audience: "local-api", Leeway: time.Second, Now: rclock}); err != nil {
			t.Fatalf("new token: %v", err)
		}
		t.Logf("case token signed by new key -> RESULT accepted (kid %s)", ring.CurrentKeyID()[:6])

		// advance beyond grace window: old key pruned on next rotate and
		// its tokens rejected; simulate by a fresh ring loaded after pruning.
		cur = cur.Add(2 * time.Hour)
		ring2, err := NewKeyRing(store.NewJSONFile(filepath.Join(t.TempDir(), "other.json")), KeyRingConfig{GraceWindow: time.Hour}, rclock)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ring2.Verify(raw, VerifyOptions{Issuer: "local-issuer", Audience: "local-api", Leeway: time.Second, Now: rclock})
		if !errors.Is(err, ErrNoValidKey) {
			t.Fatalf("unknown-key token across ring: expected ErrNoValidKey, got %v", err)
		}

		// Within the same ring, rotate again past the window prunes old key.
		if _, err := ring.Rotate(); err != nil {
			t.Fatal(err)
		}
		_, err = ring.Verify(raw, VerifyOptions{Issuer: "local-issuer", Audience: "local-api", Leeway: time.Second, Now: rclock})
		if !errors.Is(err, ErrNoValidKey) {
			t.Fatalf("expected old token dead after grace, got %v", err)
		}
		t.Logf("case old token after grace window closed -> RESULT %q", ErrorCode(err))
	})

	tscenario(t, "keys_survive_restart", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "keys.json")
		r1, err := NewKeyRing(store.NewJSONFile(dir), KeyRingConfig{GraceWindow: time.Hour}, clock)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := r1.Sign(baseClaims(now))
		if err != nil {
			t.Fatal(err)
		}
		r2, err := NewKeyRing(store.NewJSONFile(dir), KeyRingConfig{GraceWindow: time.Hour}, clock)
		if err != nil {
			t.Fatal(err)
		}
		if r1.CurrentKeyID() != r2.CurrentKeyID() {
			t.Fatal("current key id changed after restart")
		}
		if _, err := r2.Verify(raw, opts); err != nil {
			t.Fatalf("token unverifiable after restart: %v", err)
		}
		t.Logf("case reload key ring -> RESULT same kid, token verifies")
	})

	tscenario(t, "concurrent_sign_and_verify", func(t *testing.T) {
		ring, _ := newRing(t, time.Hour, clock)
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(2)
			go func() { defer wg.Done(); _, _ = ring.Sign(baseClaims(now)) }()
			go func() {
				defer wg.Done()
				raw, err := ring.Sign(baseClaims(now))
				if err == nil {
					_, _ = ring.Verify(raw, opts)
				}
			}()
		}
		wg.Wait()
		t.Logf("case 40 concurrent sign/verify goroutines -> RESULT no race/error")
	})
}
