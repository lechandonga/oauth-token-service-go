// Package token signs and verifies compact signed access tokens (JWT-style,
// HS256) and manages the signing key ring. During key rotation, tokens signed
// by a retired key remain verifiable until that key's grace window closes.
package token

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Registered and service claims carried by every access token.
type Claims struct {
	Issuer    string            `json:"iss"`
	Subject   string            `json:"sub"`
	Audience  Audience          `json:"aud"`
	IssuedAt  int64             `json:"iat"`
	NotBefore int64             `json:"nbf,omitempty"`
	ExpiresAt int64             `json:"exp"`
	ID        string            `json:"jti"`
	SessionID string            `json:"sid"`
	Scope     string            `json:"scope,omitempty"`
	Extra     map[string]string `json:"extra,omitempty"`
}

// Audience is the list of resource servers the token is intended for.
type Audience []string

func (a *Audience) UnmarshalJSON(raw []byte) error {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		*a = Audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return fmt.Errorf("%w: audience must be string or array", ErrMalformed)
	}
	*a = Audience(many)
	return nil
}

func b64Encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64Decode(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return b, nil
}

// Sign produces header.payload.signature using HS256.
func sign(secret []byte, header, payload []byte) string {
	signingInput := b64Encode(header) + "." + b64Encode(payload)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64Encode(mac.Sum(nil))
}

// verifySignature checks the signature against a candidate key without
// revealing any low-level cryptographic detail in the error.
func verifySignature(secret, signingInput, sig []byte) error {
	mac := hmac.New(sha256.New, secret)
	mac.Write(signingInput)
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, sig) {
		return ErrSignature
	}
	return nil
}

var staticHeader = func() []byte {
	raw, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	return raw
}()

// newTokenID returns a cryptographically random unique token identifier.
func newTokenID() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64Encode(b), nil
}

// VerifyOptions controls claim validation.
type VerifyOptions struct {
	Issuer string
	// Audience that must be present in the token's "aud".
	Audience string
	// Leeway tolerates small clock differences between machines.
	Leeway time.Duration
	Now    func() time.Time
}

func parseCompact(raw string, keyFor func(kid string, now time.Time) ([]byte, error), opts VerifyOptions) (*Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, ErrMalformed
	}
	headerRaw, err := b64Decode(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, fmt.Errorf("%w: bad header", ErrMalformed)
	}
	if header.Alg != "HS256" || header.Typ != "JWT" || header.Kid == "" {
		return nil, ErrMalformed
	}

	payload, err := b64Decode(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	var claims Claims
	dec := json.NewDecoder(bytes.NewReader(payload))
	if err := dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("%w: bad claims", ErrMalformed)
	}

	sig, err := b64Decode(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}

	now := time.Now()
	if opts.Now != nil {
		now = opts.Now()
	}
	secret, err := keyFor(header.Kid, now)
	if err != nil {
		if errors.Is(err, ErrNoValidKey) {
			return nil, err
		}
		// Never surface underlying crypto/storage errors verbatim.
		return nil, ErrSignature
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	if err := verifySignature(secret, signingInput, sig); err != nil {
		return nil, err
	}

	leeway := int64(opts.Leeway.Seconds())
	if leeway < 0 {
		leeway = 0
	}
	nowUnix := now.Unix()
	if claims.ExpiresAt != 0 && nowUnix > claims.ExpiresAt+leeway {
		return nil, ErrTokenExpired
	}
	if claims.NotBefore != 0 && nowUnix < claims.NotBefore-leeway {
		return nil, ErrNotYetValid
	}
	if opts.Issuer != "" && claims.Issuer != opts.Issuer {
		return nil, ErrIssuerMismatch
	}
	if opts.Audience != "" {
		found := false
		for _, a := range claims.Audience {
			if a == opts.Audience {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrAudienceMissing
		}
	}
	return &claims, nil
}
