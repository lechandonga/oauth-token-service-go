// Package token 实现访问令牌的签发与校验。
// 令牌为紧凑序列化的 HS256 JWT（仅用标准库 crypto/hmac + crypto/sha256）。
// 支持密钥轮换宽限窗口与轻微时钟偏差容忍，并且校验失败时
// 返回可区分的原因码，底层加解密细节不会透出给调用方。
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal"
	"github.com/lechandonga/oauth-token-service-go/internal/store"
)

// Claims 是访问令牌的声明集合。
type Claims struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	JTI      string `json:"jti"`
	ClientID string `json:"client_id"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
	KeyID    string `json:"kid"`
}

// Manager 负责签发与校验，参数由服务层装配。
type Manager struct {
	store       *store.Store
	issuer      string
	audience    string
	graceWindow time.Duration
	leeway      time.Duration
	now         func() time.Time
}

// NewManager 创建令牌管理器。
func NewManager(st *store.Store, issuer, audience string, graceWindow, leeway time.Duration, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{store: st, issuer: issuer, audience: audience, graceWindow: graceWindow, leeway: leeway, now: now}
}

var b64 = base64.RawURLEncoding

// Issue 使用当前 active 密钥签发一个访问令牌。
func (m *Manager) Issue(subject, clientID, jti string, ttl time.Duration) (string, Claims, error) {
	now := m.now()
	var key store.Key
	found := false
	m.store.View(func(st *store.State) {
		for i := range st.Keys {
			if st.Keys[i].Active() {
				key = st.Keys[i]
				found = true
			}
		}
	})
	if !found {
		return "", Claims{}, internal.NewE(internal.CodeKeyUnavailable, "no active signing key")
	}
	c := Claims{
		Issuer:   m.issuer,
		Subject:  subject,
		Audience: m.audience,
		JTI:      jti,
		ClientID: clientID,
		IssuedAt: now.Unix(),
		Expires:  now.Add(ttl).Unix(),
		KeyID:    key.ID,
	}
	signed, err := sign(c, key.Secret)
	if err != nil {
		return "", Claims{}, internal.WrapE(internal.CodeKeyUnavailable, "sign failed", err)
	}
	return signed, c, nil
}

func sign(c Claims, secret []byte) (string, error) {
	header := `{"alg":"HS256","typ":"JWT","kid":"` + c.KeyID + `"}`
	hb, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString(hb)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := b64.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig, nil
}

// Verify 校验签名、密钥宽限窗口、有效期、签发方与受众。
func (m *Manager) Verify(raw string) (Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Claims{}, internal.NewE(internal.CodeMalformedToken, "token must have 3 parts")
	}
	headerBytes, err := b64.DecodeString(parts[0])
	if err != nil {
		return Claims{}, internal.WrapE(internal.CodeMalformedToken, "bad header encoding", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return Claims{}, internal.WrapE(internal.CodeMalformedToken, "bad header", err)
	}
	if header.Alg != "HS256" {
		return Claims{}, internal.NewE(internal.CodeBadSignature, "unsupported alg")
	}

	key, err := m.usableKey(header.KID)
	if err != nil {
		return Claims{}, err
	}

	signingInput := parts[0] + "." + parts[1]
	expected := hmac.New(sha256.New, key.Secret)
	expected.Write([]byte(signingInput))
	gotSig, err := b64.DecodeString(parts[2])
	if err != nil {
		// 不把 base64/hmac 的底层错误文本透出
		return Claims{}, internal.NewE(internal.CodeBadSignature, "signature verification failed")
	}
	if !hmac.Equal(expected.Sum(nil), gotSig) {
		return Claims{}, internal.NewE(internal.CodeBadSignature, "signature verification failed")
	}

	claimBytes, err := b64.DecodeString(parts[1])
	if err != nil {
		return Claims{}, internal.NewE(internal.CodeMalformedToken, "bad claims encoding")
	}
	var c Claims
	if err := json.Unmarshal(claimBytes, &c); err != nil {
		return Claims{}, internal.WrapE(internal.CodeMalformedToken, "bad claims", err)
	}

	now := m.now()
	// 容忍轻微时钟偏差：leeway 窗口内的过期/未来签发都视为有效。
	if now.Add(m.leeway).Unix() < c.IssuedAt {
		return Claims{}, internal.NewE(internal.CodeMalformedToken, "token issued in the future")
	}
	if now.Add(-m.leeway).Unix() >= c.Expires {
		return c, internal.NewE(internal.CodeTokenExpired, "token expired")
	}
	if c.Issuer != m.issuer {
		return c, internal.NewE(internal.CodeTokenIssuer, "issuer mismatch")
	}
	if c.Audience != m.audience {
		return c, internal.NewE(internal.CodeTokenAudience, "audience mismatch")
	}
	return c, nil
}

// usableKey 按 kid 找密钥：active 密钥始终可用；已轮换密钥仅在
// 轮换后的 graceWindow 宽限窗口内可用，超过窗口明确失效。
func (m *Manager) usableKey(kid string) (store.Key, error) {
	now := m.now()
	var found store.Key
	ok := false
	m.store.View(func(st *store.State) {
		for _, k := range st.Keys {
			if k.ID != kid {
				continue
			}
			if k.Active() {
				found, ok = k, true
				return
			}
			if now.Sub(k.RotatedAt) <= m.graceWindow {
				found, ok = k, true
			}
		}
	})
	if !ok {
		return store.Key{}, internal.NewE(internal.CodeBadSignature, "signing key not available")
	}
	return found, nil
}
