// Package authcode 管理授权码（Authorization Code + PKCE）。
// 授权码一次性、短时效，仅保存在内存中（生命周期以分钟计，
// 重启丢失不影响安全语义）；兑换操作整体加锁，保证并发重放
// 时只有一个请求成功。
package authcode

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal"
)

// Code 是一条已签发的授权码记录。
type Code struct {
	Value       string
	ClientID    string
	RedirectURI string
	Challenge   string // code_challenge (S256 摘要)
	Subject     string
	ExpiresAt   time.Time
	used        bool
}

// Manager 保存并消费授权码。
type Manager struct {
	mu    sync.Mutex
	codes map[string]*Code
	ttl   time.Duration
	now   func() time.Time
}

// NewManager 创建管理器。
func NewManager(ttl time.Duration, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{codes: map[string]*Code{}, ttl: ttl, now: now}
}

var b64 = base64.RawURLEncoding

// Create 生成一个新授权码。
func (m *Manager) Create(clientID, redirectURI, challenge, subject string) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	value := b64.EncodeToString(raw)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[value] = &Code{
		Value:       value,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Challenge:   challenge,
		Subject:     subject,
		ExpiresAt:   m.now().Add(m.ttl),
	}
	return value, nil
}

// Exchange 校验并一次性消费授权码。失败原因通过 internal.ErrorCode 区分：
// invalid_grant（不存在/已使用）、code_expired、params_tampered、
// pkce_verifier_mismatch。
func (m *Manager) Exchange(value, clientID, redirectURI, verifier string) (*Code, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c := m.codes[value]
	if c == nil || c.used {
		return nil, internal.NewE(internal.CodeInvalidGrant, "unknown or reused authorization code")
	}
	if m.now().After(c.ExpiresAt) {
		return nil, internal.NewE(internal.CodeCodeExpired, "authorization code expired")
	}
	if c.ClientID != clientID || c.RedirectURI != redirectURI {
		return nil, internal.NewE(internal.CodeParamsTampered, "client_id or redirect_uri changed")
	}
	if !checkPKCE(c.Challenge, verifier) {
		return nil, internal.NewE(internal.CodePKCEMismatch, "code_verifier does not match code_challenge")
	}
	// 校验全部通过后原子消费。失败的校验不消耗授权码（客户端可更正后重试），
	// 而兑换全程持锁，并发重放时只会有一个请求走到这里。
	c.used = true
	return c, nil
}

// checkPKCE 按 S256 校验：BASE64URL(SHA256(verifier)) == challenge。
func checkPKCE(challenge, verifier string) bool {
	if verifier == "" || len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := b64.EncodeToString(sum[:])
	return constantEqual(challenge, got)
}

func constantEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// ValidChallenge 校验 code_challenge 本身格式是否合规（43~128 字符）。
func ValidChallenge(challenge string) bool {
	return len(challenge) >= 43 && len(challenge) <= 128
}
