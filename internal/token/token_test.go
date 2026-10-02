package token_test

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal"
	"github.com/lechandonga/oauth-token-service-go/internal/store"
	"github.com/lechandonga/oauth-token-service-go/internal/token"
)

type clock struct{ t time.Time }

func newManagerT(t *testing.T, grace time.Duration, now func() time.Time) (*token.Manager, *store.Store) {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return token.NewManager(st, "iss", "aud", grace, 60*time.Second, now), st
}

func logResult(t *testing.T, scenario, tc string, err error, want internal.ErrorCode) {
	t.Helper()
	var got internal.ErrorCode
	if err != nil {
		got = internal.CodeOf(err)
	}
	ok := got == want
	t.Logf("[场景] %-14s 用例=%-24s 结果=%s (got=%q want=%q)",
		scenario, tc, map[bool]string{true: "PASS", false: "FAIL"}[ok], got, want)
	if !ok {
		t.Fatalf("%s/%s: got %q want %q (%v)", scenario, tc, got, want, err)
	}
}

func TestVerifyFailures(t *testing.T) {
	base := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	c := &clock{t: base}
	m, _ := newManagerT(t, time.Hour, func() time.Time { return c.t })

	access, _, err := m.Issue("alice", "c1", "jti-1", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("正常校验", func(t *testing.T) {
		_, err := m.Verify(access)
		logResult(t, "访问令牌", "未过期且签名正确", err, "")
	})

	t.Run("过期", func(t *testing.T) {
		c.t = base.Add(11 * time.Minute)
		_, err := m.Verify(access)
		logResult(t, "访问令牌", "超过 exp", err, internal.CodeTokenExpired)
	})

	t.Run("时钟偏差内不过期", func(t *testing.T) {
		c.t = base.Add(10*time.Minute + 30*time.Second)
		_, err := m.Verify(access)
		logResult(t, "访问令牌", "过期 30s < leeway", err, "")
	})

	t.Run("超出时钟偏差过期", func(t *testing.T) {
		c.t = base.Add(10*time.Minute + 61*time.Second)
		_, err := m.Verify(access)
		logResult(t, "访问令牌", "过期 61s > leeway", err, internal.CodeTokenExpired)
		c.t = base
	})

	t.Run("签名篡改", func(t *testing.T) {
		tampered := access
		if strings.HasSuffix(tampered, "A") {
			tampered = strings.TrimSuffix(tampered, "A") + "B"
		} else {
			tampered = tampered[:len(tampered)-1] + "A"
		}
		_, err := m.Verify(tampered)
		logResult(t, "访问令牌", "改动签名字节", err, internal.CodeBadSignature)
	})

	t.Run("载荷被改", func(t *testing.T) {
		parts := strings.Split(access, ".")
		raw, derr := base64.RawURLEncoding.DecodeString(parts[1])
		if derr != nil {
			t.Fatal(derr)
		}
		var claims map[string]any
		if uerr := json.Unmarshal(raw, &claims); uerr != nil {
			t.Fatal(uerr)
		}
		claims["sub"] = "mallory"
		modified, _ := json.Marshal(claims)
		parts[1] = base64.RawURLEncoding.EncodeToString(modified)
		_, err := m.Verify(strings.Join(parts, "."))
		logResult(t, "访问令牌", "改动 sub 声明", err, internal.CodeBadSignature)
	})

	t.Run("格式错误", func(t *testing.T) {
		_, err := m.Verify("not-a-jwt")
		logResult(t, "访问令牌", "不是三段式", err, internal.CodeMalformedToken)
	})

}

func TestIssuerAudienceMismatch(t *testing.T) {
	base := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	c := &clock{t: base}
	m, st := newManagerT(t, time.Hour, func() time.Time { return c.t })
	access, _, err := m.Issue("alice", "c1", "jti", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("签发方不符", func(t *testing.T) {
		wrongIss := token.NewManager(st, "evil", "aud", time.Hour, 60*time.Second, func() time.Time { return c.t })
		_, err := wrongIss.Verify(access)
		logResult(t, "访问令牌", "iss 不匹配", err, internal.CodeTokenIssuer)
	})

	t.Run("受众不符", func(t *testing.T) {
		wrongAud := token.NewManager(st, "iss", "other-aud", time.Hour, 60*time.Second, func() time.Time { return c.t })
		_, err := wrongAud.Verify(access)
		logResult(t, "访问令牌", "aud 不匹配", err, internal.CodeTokenAudience)
	})
}

func TestKeyRotationGrace(t *testing.T) {
	base := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	c := &clock{t: base}
	st, err := store.New(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	m := token.NewManager(st, "iss", "aud", time.Hour, 60*time.Second, func() time.Time { return c.t })

	oldAccess, _, err := m.Issue("alice", "c1", "jti-old", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.NewKey(base); err != nil {
		t.Fatal(err)
	}

	t.Run("宽限窗口内旧令牌可用", func(t *testing.T) {
		c.t = base.Add(30 * time.Minute)
		_, err := m.Verify(oldAccess)
		logResult(t, "密钥轮换", "轮换后 30m", err, "")
	})

	t.Run("超过宽限窗口旧令牌失效", func(t *testing.T) {
		c.t = base.Add(61 * time.Minute)
		_, err := m.Verify(oldAccess)
		logResult(t, "密钥轮换", "轮换后 61m", err, internal.CodeBadSignature)
	})

	t.Run("新密钥签发的令牌正常", func(t *testing.T) {
		newAccess, _, err := m.Issue("bob", "c1", "jti-new", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		_, err = m.Verify(newAccess)
		logResult(t, "密钥轮换", "新密钥签发", err, "")
	})
}
