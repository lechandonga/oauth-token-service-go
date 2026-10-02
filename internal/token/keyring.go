package token

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal/store"
)

// key is one versioned HMAC secret with its rotation state.
type key struct {
	ID        string    `json:"id"`
	Secret    string    `json:"secret"` // base64 raw
	CreatedAt time.Time `json:"created_at"`
	// RetiredAt is zero while the key is current; once set it only verifies
	// tokens until CreatedAt+TokenLifetime horizon enforced by grace.
	RetiredAt time.Time `json:"retired_at,omitempty"`
	// GraceUntil is the absolute cutoff after which tokens signed by this
	// retired key are rejected.
	GraceUntil time.Time `json:"grace_until,omitempty"`
}

// KeyRingConfig configures rotation defaults.
type KeyRingConfig struct {
	// GraceWindow is how long after rotation tokens from the retired key
	// remain verifiable. Should cover the maximum access-token lifetime.
	GraceWindow time.Duration
}

// KeyRing holds the current signing key plus retired keys inside their window.
type KeyRing struct {
	persist *store.JSONFile
	cfg     KeyRingConfig
	now     func() time.Time

	mu   sync.Mutex
	keys []*key // newest first
}

// NewKeyRing loads persisted keys, or bootstraps a fresh current key.
func NewKeyRing(persist *store.JSONFile, cfg KeyRingConfig, now func() time.Time) (*KeyRing, error) {
	if now == nil {
		now = time.Now
	}
	if cfg.GraceWindow <= 0 {
		cfg.GraceWindow = 24 * time.Hour
	}
	r := &KeyRing{persist: persist, cfg: cfg, now: now}

	var doc struct {
		Keys []*key `json:"keys"`
	}
	if err := persist.Load(&doc); err != nil {
		return nil, fmt.Errorf("token: load key ring: %w", err)
	}
	r.keys = doc.Keys
	if len(r.keys) == 0 {
		if err := r.rotateLocked(); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func newKeyID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func newSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Rotate issues a new current key and retires the previous one with a grace
// window. Retired keys older than their window are pruned.
func (r *KeyRing) Rotate() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.keys[0].ID, r.rotateLocked()
}

// rotateLocked performs rotation; caller holds r.mu (or is single-threaded
// construction).
func (r *KeyRing) rotateLocked() error {
	now := r.now()
	id, err := newKeyID()
	if err != nil {
		return err
	}
	secret, err := newSecret()
	if err != nil {
		return err
	}
	current := &key{ID: id, Secret: secret, CreatedAt: now}

	next := []*key{current}
	for _, k := range r.keys {
		if k.RetiredAt.IsZero() {
			k.RetiredAt = now
			k.GraceUntil = now.Add(r.cfg.GraceWindow)
		}
		if now.Before(k.GraceUntil) {
			next = append(next, k)
		}
	}
	r.keys = next
	return r.saveLocked()
}

func (r *KeyRing) saveLocked() error {
	return r.persist.Save(struct {
		Keys []*key `json:"keys"`
	}{Keys: r.keys})
}

func (k *key) secretBytes() []byte {
	b, _ := base64.RawURLEncoding.DecodeString(k.Secret)
	return b
}

// currentKey returns the signing key snapshot.
func (r *KeyRing) currentKey() *key {
	return r.keys[0]
}

// keyForVerification resolves a "kid" to a usable secret: the current key
// always works; a retired key works only before its grace cutoff.
func (r *KeyRing) keyForVerification(kid string, now time.Time) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, k := range r.keys {
		if k.ID != kid {
			continue
		}
		if k.RetiredAt.IsZero() {
			return k.secretBytes(), nil
		}
		if now.Before(k.GraceUntil) {
			return k.secretBytes(), nil
		}
		return nil, ErrNoValidKey
	}
	return nil, ErrNoValidKey
}

// Sign issues a signed compact token for the claims. ID, IssuedAt and the
// signing "kid" are filled in automatically.
func (r *KeyRing) Sign(c Claims) (string, error) {
	r.mu.Lock()
	sk := r.currentKey()
	kid := sk.ID
	secret := append([]byte(nil), sk.secretBytes()...)
	r.mu.Unlock()

	if c.ID == "" {
		id, err := newTokenID()
		if err != nil {
			return "", err
		}
		c.ID = id
	}
	now := r.now().Unix()
	if c.IssuedAt == 0 {
		c.IssuedAt = now
	}
	if c.NotBefore == 0 {
		c.NotBefore = now
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	header := []byte(fmt.Sprintf(`{"alg":"HS256","typ":"JWT","kid":%q}`, kid))
	return sign(secret, header, payload), nil
}

// Verify validates signature (respecting rotation grace) and claims.
func (r *KeyRing) Verify(raw string, opts VerifyOptions) (*Claims, error) {
	return parseCompact(raw, r.keyForVerification, opts)
}

// CurrentKeyID exposes the active key id (for diagnostics/tests).
func (r *KeyRing) CurrentKeyID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.keys[0].ID
}
