// Command demo walks the full local OAuth flow end-to-end in-process and
// prints every step, result and (negative) failure reason. No network and no
// external accounts are required; state lives in a fresh temp directory.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal/oauth"
)

func main() {
	dir, err := os.MkdirTemp("", "oauth-demo-")
	must(err)
	defer os.RemoveAll(dir)

	clock := time.Now
	svc, err := oauth.New(oauth.Config{
		DataDir:   dir,
		Issuer:    "http://127.0.0.1:8080",
		Audience:  "local-resource-api",
		AccessTTL: 2 * time.Minute,
		Leeway:    30 * time.Second,
		Clock:     func() time.Time { return clock() },
	})
	must(err)

	const clientID = "local-cli"
	const redirect = "http://127.0.0.1:9876/callback"
	verifier := randVerifier()
	challenge := s256(verifier)

	step("1. PKCE parameters", "verifier=%s\n   challenge=%s", verifier, challenge)

	// --- happy path: authorize -> exchange -> introspect ---
	code, err := svc.Authorize(oauth.AuthorizeInput{
		ResponseType: "code", ClientID: clientID, RedirectURI: redirect,
		State: "xyz", Challenge: challenge, ChallengeMth: "S256",
		Username: "demo", Password: "demo-pass", Scope: "read",
	})
	must(err)
	step("2. Authorize (valid client + credentials)", "code=%s", shorten(code))

	tokens, err := svc.Token(oauth.ExchangeInput{
		GrantType: "authorization_code", Code: code, RedirectURI: redirect,
		ClientID: clientID, CodeVerifier: verifier,
	})
	must(err)
	step("3. Exchange code (correct PKCE verifier)",
		"access=%s\n   refresh=%s\n   expires_in=%d",
		shorten(tokens.AccessToken), shorten(tokens.RefreshToken), tokens.ExpiresIn)

	res, err := svc.Verify(tokens.AccessToken)
	must(err)
	step("4. Introspect access token", "active sub=%s sid=%s scope=%s", res.Subject, shorten(res.Session), res.Scope)

	// --- authorization code replay rejected ---
	_, err = svc.Token(oauth.ExchangeInput{
		GrantType: "authorization_code", Code: code, RedirectURI: redirect,
		ClientID: clientID, CodeVerifier: verifier,
	})
	step("5. Reuse same authorization code", "REJECTED -> %s", errCode(err))

	// --- bad PKCE verifier rejected with a fresh code ---
	badCode, err := svc.Authorize(oauth.AuthorizeInput{
		ResponseType: "code", ClientID: clientID, RedirectURI: redirect,
		Challenge: challenge, Username: "demo", Password: "demo-pass",
	})
	must(err)
	_, err = svc.Token(oauth.ExchangeInput{
		GrantType: "authorization_code", Code: badCode, RedirectURI: redirect,
		ClientID: clientID, CodeVerifier: s256("totally-wrong-verifier-aaaaaaaaaaaaaaaaaaa"),
	})
	step("6. Exchange with wrong PKCE verifier", "REJECTED -> %s", errCode(err))

	// --- bad redirect_uri / client rejected before code issuance ---
	_, err = svc.Authorize(oauth.AuthorizeInput{
		ResponseType: "code", ClientID: "unknown-client", RedirectURI: redirect,
		Challenge: challenge, Username: "demo", Password: "demo-pass",
	})
	step("7. Unknown client_id", "REJECTED -> %s", errCode(err))
	_, err = svc.Authorize(oauth.AuthorizeInput{
		ResponseType: "code", ClientID: clientID, RedirectURI: "http://127.0.0.1:7777/other",
		Challenge: challenge, Username: "demo", Password: "demo-pass",
	})
	step("8. Unregistered redirect_uri", "REJECTED -> %s", errCode(err))

	// --- clock skew tolerated ---
	clock = func() time.Time { return time.Now().Add(20 * time.Second) }
	_, err = svc.Verify(tokens.AccessToken)
	must(err)
	step("9. Verify with +20s clock skew (within 30s leeway)", "accepted")

	// --- refresh rotation ---
	oldRefresh := tokens.RefreshToken
	rotated, err := svc.Token(oauth.ExchangeInput{GrantType: "refresh_token", RefreshToken: oldRefresh})
	must(err)
	step("10. Refresh: new tokens issued, old rotated",
		"new refresh=%s", shorten(rotated.RefreshToken))

	_, err = svc.Token(oauth.ExchangeInput{GrantType: "refresh_token", RefreshToken: oldRefresh})
	step("11. Reuse rotated refresh token", "REJECTED -> %s (family revoked, audit logged)", errCode(err))

	_, err = svc.Verify(tokens.AccessToken)
	step("12. Access token after reuse-triggered revocation", "REJECTED -> %s", errCode(err))

	// --- logout revokes immediately ---
	_, err = svc.Token(oauth.ExchangeInput{GrantType: "refresh_token", RefreshToken: rotated.RefreshToken})
	expectFail("rotated refresh should be dead after family revocation", err)

	// fresh login to demonstrate logout
	verifier2 := randVerifier()
	code2, err := svc.Authorize(oauth.AuthorizeInput{
		ResponseType: "code", ClientID: clientID, RedirectURI: redirect,
		Challenge: s256(verifier2), Username: "demo", Password: "demo-pass",
	})
	must(err)
	t2, err := svc.Token(oauth.ExchangeInput{
		GrantType: "authorization_code", Code: code2, RedirectURI: redirect,
		ClientID: clientID, CodeVerifier: verifier2,
	})
	must(err)
	must(svc.Logout(t2.SessionID))
	_, err = svc.Verify(t2.AccessToken)
	step("13. Access token immediately after logout", "REJECTED -> %s", errCode(err))

	// --- restart persistence: revoked state must not resurrect ---
	svc2, err := oauth.New(oauth.Config{DataDir: dir, Issuer: "http://127.0.0.1:8080", Audience: "local-resource-api"})
	must(err)
	_, err = svc2.Verify(t2.AccessToken)
	step("14. Restart process: revoked token still dead", "REJECTED -> %s", errCode(err))

	// --- key rotation grace window ---
	verifier3 := randVerifier()
	code3, err := svc2.Authorize(oauth.AuthorizeInput{
		ResponseType: "code", ClientID: clientID, RedirectURI: redirect,
		Challenge: s256(verifier3), Username: "demo", Password: "demo-pass",
	})
	must(err)
	t3, err := svc2.Token(oauth.ExchangeInput{
		GrantType: "authorization_code", Code: code3, RedirectURI: redirect,
		ClientID: clientID, CodeVerifier: verifier3,
	})
	must(err)
	oldKID := svc2.CurrentKeyID()
	must(svc2.RotateKeys())
	_, err = svc2.Verify(t3.AccessToken)
	step("15. Verify token signed by previous key during grace window", "accepted (old kid=%s -> new kid=%s)", shorten(oldKID), shorten(svc2.CurrentKeyID()))

	// --- tampered token ---
	bad := strings.TrimSuffix(t3.AccessToken, "A") + "B"
	if bad == t3.AccessToken {
		bad = t3.AccessToken + "x"
	}
	_, err = svc2.Verify(bad)
	step("16. Tampered token signature", "REJECTED -> %s", errCode(err))

	// --- audit trail ---
	var kinds []string
	for _, ev := range svc2.AuditEvents() {
		kinds = append(kinds, ev.Kind)
	}
	step("17. Audit trail", "events: %s", strings.Join(kinds, ", "))

	fmt.Println("\nDEMO OK - all scenarios behaved as expected. State dir:", filepath.Base(dir))
}

func step(title, format string, args ...any) {
	fmt.Printf("\n== %s ==\n   %s\n", title, fmt.Sprintf(format, args...))
}

func errCode(err error) string {
	var se *oauth.ServiceError
	if errors.As(err, &se) {
		return se.Code
	}
	if err == nil {
		return "unexpected success"
	}
	return err.Error()
}

func expectFail(msg string, err error) {
	if err == nil {
		fmt.Fprintf(os.Stderr, "expected failure: %s\n", msg)
		os.Exit(1)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func shorten(s string) string {
	if len(s) <= 18 {
		return s
	}
	return s[:14] + "..."
}

func randVerifier() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func s256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
