package store

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func sscenario(t *testing.T, name string, fn func(t *testing.T)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Logf("SCENARIO %s: START", name)
		fn(t)
		t.Logf("SCENARIO %s: PASS", name)
	})
}

func newStore(t *testing.T, now func() time.Time) (*SessionStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "sessions.json")
	s, err := NewSessionStore(NewJSONFile(dir), now)
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	return s, dir
}

func reloadStore(t *testing.T, dir string, now func() time.Time) *SessionStore {
	s, err := NewSessionStore(NewJSONFile(dir), now)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	return s
}

func hasEventKind(events []AuditEvent, kind string) bool {
	for _, e := range events {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

func TestRefreshAndRevocationScenarios(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	ttl := time.Hour

	sscenario(t, "rotation_issues_new_refresh_and_retires_old", func(t *testing.T) {
		s, _ := newStore(t, clock)
		sid, rt, err := s.CreateSession("demo", "local-cli", "read", ttl)
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.Rotate(rt, ttl)
		if err != nil {
			t.Fatalf("rotate: %v", err)
		}
		if res.NewRefresh == rt || res.Session.ID != sid {
			t.Fatal("rotation did not produce a distinct token for the same session")
		}
		if !s.SessionActive(sid) {
			t.Fatal("session should remain active")
		}
		t.Logf("case rotate -> RESULT old retired, new token issued for sid=%s", sid[:6])
	})

	sscenario(t, "reuse_of_rotated_token_revokes_entire_family", func(t *testing.T) {
		s, _ := newStore(t, clock)
		_, rt1, err := s.CreateSession("demo", "local-cli", "read", ttl)
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.Rotate(rt1, ttl)
		if err != nil {
			t.Fatal(err)
		}
		rt2 := res.NewRefresh

		// attacker replays rt1
		_, errReplay := s.Rotate(rt1, ttl)
		if !errors.Is(errReplay, ErrRefreshUsed) {
			t.Fatalf("first replay expected ErrRefreshUsed, got %v", errReplay)
		}
		t.Logf("case replay old token -> RESULT %q", "refresh_used")

		// whole family dead: legitimate rt2 must fail too
		if _, err := s.Rotate(rt2, ttl); !errors.Is(err, ErrFamilyRevoked) {
			t.Fatalf("valid successor after family revoke expected ErrFamilyRevoked, got %v", err)
		}
		// repeated replay keeps returning revoked state
		if _, err := s.Rotate(rt1, ttl); !errors.Is(err, ErrFamilyRevoked) {
			t.Fatalf("repeat replay expected ErrFamilyRevoked, got %v", err)
		}
		events := s.Events()
		if !hasEventKind(events, "family_revoked") {
			t.Fatal("expected family_revoked audit event")
		}
		t.Logf("case legitimate successor and repeat replay -> RESULT family_revoked; audit trail contains family_revoked")
	})

	sscenario(t, "logout_revokes_session_immediately", func(t *testing.T) {
		s, _ := newStore(t, clock)
		sid, rt, err := s.CreateSession("demo", "local-cli", "read", ttl)
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.Rotate(rt, ttl)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeSession(sid, "logout"); err != nil {
			t.Fatal(err)
		}
		if s.SessionActive(sid) {
			t.Fatal("session still active after logout")
		}
		if _, err := s.Rotate(res.NewRefresh, ttl); !errors.Is(err, ErrFamilyRevoked) {
			t.Fatalf("refresh after logout: got %v", err)
		}
		if !hasEventKind(s.Events(), "logout") {
			t.Fatal("logout audit event missing")
		}
		t.Logf("case logout -> RESULT session inactive, refresh rejected, logout audited")
	})

	sscenario(t, "revoke_endpoint_kills_family", func(t *testing.T) {
		s, _ := newStore(t, clock)
		sid, rt, err := s.CreateSession("demo", "local-cli", "read", ttl)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeRefresh(rt, "revocation_endpoint"); err != nil {
			t.Fatal(err)
		}
		if s.SessionActive(sid) {
			t.Fatal("session still active after refresh revocation")
		}
		_, err = s.Rotate(rt, ttl)
		if !errors.Is(err, ErrFamilyRevoked) {
			t.Fatalf("rotating revoked token: got %v", err)
		}
		t.Logf("case RFC7009 revoke -> RESULT family_revoked")
	})

	sscenario(t, "expired_refresh_rejected", func(t *testing.T) {
		tm := now
		c := func() time.Time { return tm }
		s, _ := newStore(t, c)
		_, rt, err := s.CreateSession("demo", "local-cli", "read", 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		tm = tm.Add(11 * time.Second)
		_, err = s.Rotate(rt, ttl)
		if !errors.Is(err, ErrRefreshExpired) {
			t.Fatalf("expected ErrRefreshExpired, got %v", err)
		}
		t.Logf("case rotate past expiry -> RESULT refresh_expired")
	})

	sscenario(t, "unknown_token_does_not_panic_and_is_traced", func(t *testing.T) {
		s, _ := newStore(t, clock)
		_, err := s.Rotate("does-not-exist", ttl)
		if !errors.Is(err, ErrRefreshNotFound) {
			t.Fatalf("expected ErrRefreshNotFound, got %v", err)
		}
		if !hasEventKind(s.Events(), "refresh_unknown") {
			t.Fatal("expected refresh_unknown audit event")
		}
		if err := s.RevokeRefresh("does-not-exist", "revocation_endpoint"); err != nil {
			t.Fatalf("revoking unknown token should be idempotent: %v", err)
		}
		t.Logf("case unknown token rotate/revoke -> RESULT not_found + idempotent revoke, audited")
	})

	sscenario(t, "state_survives_restart", func(t *testing.T) {
		s, dir := newStore(t, clock)
		sid, rt1, err := s.CreateSession("demo", "local-cli", "read", ttl)
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.Rotate(rt1, ttl)
		if err != nil {
			t.Fatal(err)
		}
		rt2 := res.NewRefresh
		// replay rt1 -> revoke family before restart
		if _, err := s.Rotate(rt1, ttl); !errors.Is(err, ErrRefreshUsed) {
			t.Fatalf("replay before restart: got %v", err)
		}
		if !s.SessionActive(sid) {
			t.Logf("case family revoked pre-restart as expected")
		}

		s2 := reloadStore(t, dir, clock)
		if s2.SessionActive(sid) {
			t.Fatal("revoked family resurrected after restart")
		}
		if _, err := s2.Rotate(rt2, ttl); !errors.Is(err, ErrFamilyRevoked) {
			t.Fatalf("rt2 after restart: got %v", err)
		}
		if _, err := s2.Rotate(rt1, ttl); !errors.Is(err, ErrFamilyRevoked) {
			t.Fatalf("rotated token revived after restart: got %v", err)
		}
		t.Logf("case restart -> RESULT revoked session, rotated and revoked tokens stay dead")
	})

	sscenario(t, "concurrent_rotation_single_success", func(t *testing.T) {
		s, _ := newStore(t, clock)
		_, rt, err := s.CreateSession("demo", "local-cli", "read", ttl)
		if err != nil {
			t.Fatal(err)
		}
		const n = 24
		var wg sync.WaitGroup
		var mu sync.Mutex
		success, rejected := 0, 0
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := s.Rotate(rt, ttl)
				mu.Lock()
				if err == nil {
					success++
				} else {
					rejected++
				}
				mu.Unlock()
			}()
		}
		close(start)
		wg.Wait()
		if success != 1 {
			t.Fatalf("expected exactly 1 successful rotation, got %d", success)
		}
		if rejected != n-1 {
			t.Fatalf("expected %d rejections, got %d", n-1, rejected)
		}
		if s.SessionActive(s.Events()[0].SessionID) {
			t.Fatal("family must be revoked after concurrent replays")
		}
		t.Logf("case %d concurrent rotations -> RESULT success=1 rejected=%d, family revoked", n, rejected)
	})

	sscenario(t, "concurrent_rotation_of_distinct_tokens_all_succeed", func(t *testing.T) {
		s, _ := newStore(t, clock)
		const n = 10
		tokens := make([]string, n)
		for i := range tokens {
			_, rt, err := s.CreateSession("demo", "local-cli", "read", ttl)
			if err != nil {
				t.Fatal(err)
			}
			tokens[i] = rt
		}
		var wg sync.WaitGroup
		errs := make(chan error, n)
		start := make(chan struct{})
		for _, rt := range tokens {
			wg.Add(1)
			go func(rt string) {
				defer wg.Done()
				<-start
				_, err := s.Rotate(rt, ttl)
				errs <- err
			}(rt)
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("distinct token rotation failed: %v", err)
			}
		}
		t.Logf("case %d distinct sessions rotated concurrently -> RESULT all succeed", n)
	})
}
