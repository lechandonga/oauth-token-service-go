package refresh_test

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal"
	"github.com/lechandonga/oauth-token-service-go/internal/refresh"
	"github.com/lechandonga/oauth-token-service-go/internal/store"
)

type clock struct{ t time.Time }

func newSvc(t *testing.T, path string, now func() time.Time) (*refresh.Service, *store.Store) {
	t.Helper()
	st, err := store.New(path)
	if err != nil {
		t.Fatal(err)
	}
	return refresh.NewService(st, time.Hour, now), st
}

func logResult(t *testing.T, scenario, tc string, err error, want internal.ErrorCode) bool {
	t.Helper()
	var got internal.ErrorCode
	if err != nil {
		got = internal.CodeOf(err)
	}
	ok := got == want
	t.Logf("[场景] %-16s 用例=%-26s 结果=%s (got=%q want=%q)",
		scenario, tc, map[bool]string{true: "PASS", false: "FAIL"}[ok], got, want)
	if !ok {
		t.Errorf("%s/%s: got %q want %q", scenario, tc, got, want)
	}
	return ok
}

func TestRotationAndReuse(t *testing.T) {
	base := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	c := &clock{t: base}
	svc, _ := newSvc(t, filepath.Join(t.TempDir(), "state.json"), func() time.Time { return c.t })

	rt, node, err := svc.Issue("alice", "c1", "jti-1")
	if err != nil {
		t.Fatal(err)
	}
	svc.BindAccessJTI(node.FamilyID, "jti-1")

	t.Run("首次轮换成功并返回新令牌", func(t *testing.T) {
		next, _, err := svc.Rotate(rt)
		if err == nil && next != rt {
			logResult(t, "刷新轮换", "旧令牌换新", nil, "")
			rt2 = next
		} else {
			t.Fatalf("rotate failed: %v", err)
		}
	})

	t.Run("旧令牌复用：整链撤销+原因码+留痕", func(t *testing.T) {
		_, _, err := svc.Rotate(rt)
		logResult(t, scenarioReuse, "再次使用已换出令牌", err, internal.CodeReuseDetected)

		// 新令牌也应立即失效
		_, _, err = svc.Rotate(rt2)
		logResult(t, scenarioReuse, "链上当前令牌失效", err, internal.CodeInvalidGrant)

		// 关联访问令牌被撤销
		if !svc.IsAccessRevoked("jti-1") {
			t.Fatal("复用发生后关联访问令牌应被撤销")
		}
		// 审计留痕
		var found bool
		for _, ev := range auditOf(svc) {
			if ev.Kind == "refresh_reuse_detected" {
				found = true
			}
		}
		if !found {
			t.Fatal("审计日志中缺少 refresh_reuse_detected")
		}
		t.Logf("[场景] %-16s 用例=%-26s 结果=PASS", scenarioReuse, "访问令牌联动撤销+审计留痕")
	})
}

var rt2 string

const scenarioReuse = "刷新令牌复用"

func auditOf(svc *refresh.Service) []store.Event {
	return svc.AuditEvents()
}

func TestRevokeAndRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	base := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	c := &clock{t: base}

	svc, st := newSvc(t, path, func() time.Time { return c.t })
	rt, node, err := svc.Issue("alice", "c1", "jti-x")
	if err != nil {
		t.Fatal(err)
	}
	svc.BindAccessJTI(node.FamilyID, "jti-x")

	t.Run("主动撤销后令牌失效", func(t *testing.T) {
		if err := svc.RevokeToken(rt); err != nil {
			t.Fatal(err)
		}
		_, _, err := svc.Rotate(rt)
		logResult(t, "主动撤销", "撤销后再刷新", err, internal.CodeInvalidGrant)
		if !svc.IsAccessRevoked("jti-x") {
			t.Fatal("撤销刷新令牌后关联访问令牌应立即失效")
		}
	})

	t.Run("重启后撤销状态保留", func(t *testing.T) {
		// 重新打开同一个数据文件，模拟进程重启。
		svc2, _ := newSvc(t, path, func() time.Time { return c.t })
		_, _, err := svc2.Rotate(rt)
		logResult(t, "重启恢复", "已撤销令牌不复活", err, internal.CodeInvalidGrant)
		if !svc2.IsAccessRevoked("jti-x") {
			t.Fatal("重启后访问令牌撤销状态丢失")
		}
	})

	t.Run("重启后已换出令牌不复活", func(t *testing.T) {
		svc3, _ := newSvc(t, path, func() time.Time { return c.t })
		rta, _, err := svc3.Issue("bob", "c1", "jti-y")
		if err != nil {
			t.Fatal(err)
		}
		rtb, _, err := svc3.Rotate(rta)
		if err != nil {
			t.Fatal(err)
		}
		_ = rtb

		svc4, _ := newSvc(t, path, func() time.Time { return c.t })
		_, _, err = svc4.Rotate(rta)
		logResult(t, "重启恢复", "重启后复用旧令牌仍被拒绝", err, internal.CodeReuseDetected)
	})

	_ = st
}

func TestConcurrentRotate(t *testing.T) {
	base := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	c := &clock{t: base}
	svc, _ := newSvc(t, filepath.Join(t.TempDir(), "state.json"), func() time.Time { return c.t })
	rt, _, err := svc.Issue("alice", "c1", "jti-c")
	if err != nil {
		t.Fatal(err)
	}

	const n = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	codes := map[internal.ErrorCode]int{}
	distinct := map[string]bool{}
	start := make(chan struct{})
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			<-start
			next, _, err := svc.Rotate(rt)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				success++
				distinct[next] = true
			} else {
				codes[internal.CodeOf(err)]++
			}
		}()
	}
	close(start)
	wg.Wait()

	if success == 1 && len(distinct) == 1 && (codes[internal.CodeInvalidGrant]+codes[internal.CodeReuseDetected]) == n-1 {
		t.Logf("[场景] %-16s 用例=%-26s 结果=PASS (成功=%d 失败=%d)",
			"并发刷新", "32 个并发轮换", success, n-1)
	} else {
		t.Fatalf("成功=%d 唯一新令牌=%d 失败分布=%v", success, len(distinct), codes)
	}
}
