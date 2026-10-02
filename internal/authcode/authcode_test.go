package authcode

import (
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal"
)

var testB64 = base64.RawURLEncoding

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newVerifier() string {
	return testB64.EncodeToString(make([]byte, 32))
}

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return testB64.EncodeToString(sum[:])
}

func newTestManager(t *testing.T) (*Manager, *fakeClock, string, string) {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)}
	m := NewManager(time.Minute, clk.now)
	vb := make([]byte, 32)
	for i := range vb {
		vb[i] = byte(i + 1)
	}
	verifier := testB64.EncodeToString(vb) // 43 base64url chars
	challenge := challengeOf(verifier)
	return m, clk, verifier, challenge
}

// result 记录单个用例的预期与实际，t.Logf 会在用例日志里留下结果。
func result(t *testing.T, scenario, tc string, got, want internal.ErrorCode) {
	t.Helper()
	ok := got == want
	t.Logf("[场景] %-18s 用例=%-28s 结果=%v (got=%s want=%s)",
		scenario, tc, map[bool]string{true: "PASS", false: "FAIL"}[ok], got, want)
	if !ok {
		t.Errorf("%s/%s: got %s want %s", scenario, tc, got, want)
	}
}

func codeOf(err error) internal.ErrorCode {
	if err == nil {
		return ""
	}
	return internal.CodeOf(err)
}

func TestAuthorizationCodeExchange(t *testing.T) {
	scenario := "授权码兑换"

	t.Run("正常兑换成功", func(t *testing.T) {
		m, _, verifier, challenge := newTestManager(t)
		c, err := m.Create("c1", "http://cb", challenge, "alice")
		if err != nil {
			t.Fatal(err)
		}
		got, err := m.Exchange(c, "c1", "http://cb", verifier)
		if err != nil || got.Subject != "alice" {
			result(t, scenario, "正确参数", codeOf(err), "")
		} else {
			result(t, scenario, "正确参数", "", "")
		}
	})

	t.Run("重放授权码被拒绝", func(t *testing.T) {
		m, _, verifier, challenge := newTestManager(t)
		c, _ := m.Create("c1", "http://cb", challenge, "alice")
		if _, err := m.Exchange(c, "c1", "http://cb", verifier); err != nil {
			t.Fatal(err)
		}
		_, err := m.Exchange(c, "c1", "http://cb", verifier)
		result(t, scenario, "同一码第二次使用", codeOf(err), internal.CodeInvalidGrant)
	})

	t.Run("不存在的授权码", func(t *testing.T) {
		m, _, verifier, _ := newTestManager(t)
		_, err := m.Exchange("nope", "c1", "http://cb", verifier)
		result(t, scenario, "未知码", codeOf(err), internal.CodeInvalidGrant)
	})

	t.Run("授权码过期", func(t *testing.T) {
		m, clk, verifier, challenge := newTestManager(t)
		c, _ := m.Create("c1", "http://cb", challenge, "alice")
		clk.advance(2 * time.Minute)
		_, err := m.Exchange(c, "c1", "http://cb", verifier)
		result(t, scenario, "超过 TTL", codeOf(err), internal.CodeCodeExpired)
	})

	t.Run("参数被篡改", func(t *testing.T) {
		m, _, verifier, challenge := newTestManager(t)
		c, _ := m.Create("c1", "http://cb", challenge, "alice")

		t.Run("client_id 变化", func(t *testing.T) {
			_, err := m.Exchange(c, "c2", "http://cb", verifier)
			result(t, scenario, "client_id 被改", codeOf(err), internal.CodeParamsTampered)
		})
		t.Run("redirect_uri 变化", func(t *testing.T) {
			_, err := m.Exchange(c, "c1", "http://other", verifier)
			result(t, scenario, "redirect_uri 被改", codeOf(err), internal.CodeParamsTampered)
		})
	})

	t.Run("并发兑换只有一个成功", func(t *testing.T) {
		m, _, verifier, challenge := newTestManager(t)
		c, _ := m.Create("c1", "http://cb", challenge, "alice")

		const n = 32
		var wg sync.WaitGroup
		var mu sync.Mutex
		success, codes := 0, map[internal.ErrorCode]int{}
		start := make(chan struct{})
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				<-start
				_, err := m.Exchange(c, "c1", "http://cb", verifier)
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					success++
				} else {
					codes[internal.CodeOf(err)]++
				}
			}()
		}
		close(start)
		wg.Wait()
		if success == 1 && codes[internal.CodeInvalidGrant] == n-1 {
			t.Logf("[场景] %-18s 用例=%-28s 结果=PASS (成功=%d 重放失败=%d)",
				scenario, "32 个并发兑换", success, n-1)
		} else {
			t.Fatalf("成功=%d 失败分布=%v，要求恰好 1 个成功", success, codes)
		}
	})
}

func TestPKCE(t *testing.T) {
	scenario := "PKCE 校验"

	t.Run("verifier 不匹配", func(t *testing.T) {
		m, _, verifier, challenge := newTestManager(t)
		c, _ := m.Create("c1", "http://cb", challenge, "alice")
		_, err := m.Exchange(c, "c1", "http://cb", newVerifier())
		result(t, scenario, "错误 code_verifier", codeOf(err), internal.CodePKCEMismatch)
		// 失败不应消费授权码：正确 verifier 仍可兑换
		_, err = m.Exchange(c, "c1", "http://cb", verifier)
		result(t, scenario, "更正后可继续兑换", codeOf(err), "")
	})

	t.Run("verifier 格式非法", func(t *testing.T) {
		m, _, _, challenge := newTestManager(t)
		c, _ := m.Create("c1", "http://cb", challenge, "alice")
		_, err := m.Exchange(c, "c1", "http://cb", "short")
		result(t, scenario, "过短 verifier", codeOf(err), internal.CodePKCEMismatch)
	})

	t.Run("challenge 格式校验", func(t *testing.T) {
		if ValidChallenge("abc") {
			t.Fatal("过短 challenge 应判非法")
		}
		t.Logf("[场景] %-18s 用例=%-28s 结果=PASS", scenario, "challenge 长度校验")
	})
}
