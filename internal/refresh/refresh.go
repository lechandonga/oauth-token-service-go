// Package refresh 实现刷新令牌的轮换（rotation）、复用检测与撤销。
// 每次刷新都换发新令牌；一旦旧令牌被再次使用，立即撤销整条
// 令牌链（family）并写审计日志。状态通过 store 持久化，
// 重启后依然有效；兑换在 store 单锁内完成，并发刷新只有一个成功。
package refresh

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/lechandonga/oauth-token-service-go/internal"
	"github.com/lechandonga/oauth-token-service-go/internal/store"
)

// Service 基于持久化 Store 管理刷新令牌链。
type Service struct {
	store *store.Store
	ttl   time.Duration
	now   func() time.Time
}

// NewService 创建刷新令牌服务。
func NewService(st *store.Store, ttl time.Duration, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: st, ttl: ttl, now: now}
}

// Issue 为一次登录创建令牌链的第一个刷新令牌。
func (s *Service) Issue(subject, clientID, jti string) (string, *store.RefreshNode, error) {
	familyID, err := randID()
	if err != nil {
		return "", nil, err
	}
	tok, err := randID()
	if err != nil {
		return "", nil, err
	}
	now := s.now()
	node := &store.RefreshNode{
		Token:     tok,
		FamilyID:  familyID,
		Subject:   subject,
		ClientID:  clientID,
		JTI:       jti,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.ttl),
	}
	err = s.store.Mutate(func(st *store.State) error {
		st.RefreshNodes[tok] = node
		st.FamilySubject[familyID] = subject
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return tok, node, nil
}

// Rotate 消费一个刷新令牌并换发新令牌。
// 可能返回的原因码：
//   - invalid_grant:          令牌不存在 / 已正常轮换 / 已过期 / 链已撤销
//   - refresh_reuse_detected: 已轮换过的旧令牌被再次使用（整条链已撤销并留痕）
func (s *Service) Rotate(oldToken string) (newToken string, node *store.RefreshNode, err error) {
	now := s.now()
	rotateErr := s.store.Mutate(func(st *store.State) error {
		old, ok := st.RefreshNodes[oldToken]
		if !ok {
			return internal.NewE(internal.CodeInvalidGrant, "unknown refresh token")
		}
		if st.Families[old.FamilyID] {
			return internal.NewE(internal.CodeInvalidGrant, "token family revoked")
		}
		if !old.RotatedAt.IsZero() {
			// 复用检测：已经被换出的令牌再次出现，判定为失窃/重放。
			st.Families[old.FamilyID] = true
			for _, n := range st.RefreshNodes {
				if n.FamilyID == old.FamilyID {
					n.Revoked = true
				}
			}
			revokeFamilyJTIs(st, old.FamilyID, now)
			st.Audit = append(st.Audit, store.Event{
				Time:   now,
				Kind:   "refresh_reuse_detected",
				Detail: "subject=" + old.Subject + " family=" + old.FamilyID,
			})
			return internal.NewE(internal.CodeReuseDetected, "refresh token replay; family revoked")
		}
		if old.Revoked {
			return internal.NewE(internal.CodeInvalidGrant, "refresh token revoked")
		}
		if now.After(old.ExpiresAt) {
			return internal.NewE(internal.CodeInvalidGrant, "refresh token expired")
		}

		tok, err := randID()
		if err != nil {
			return err
		}
		old.RotatedAt = now
		next := &store.RefreshNode{
			Token:     tok,
			FamilyID:  old.FamilyID,
			Subject:   old.Subject,
			ClientID:  old.ClientID,
			JTI:       old.JTI,
			IssuedAt:  now,
			ExpiresAt: now.Add(s.ttl),
		}
		st.RefreshNodes[tok] = next
		newToken, node = tok, next
		return nil
	})
	if rotateErr != nil {
		return "", nil, rotateErr
	}
	return newToken, node, nil
}

func revokeFamilyJTIs(st *store.State, family string, now time.Time) {
	for _, jti := range st.FamilyJTIs[family] {
		st.RevokedJTI[jti] = now
	}
}

// BindAccessJTI 把一次新签发的访问令牌 jti 挂到刷新令牌链上，
// 这样链被撤销/复用时，该链上所有访问令牌都会立即失效。
func (s *Service) BindAccessJTI(family, jti string) {
	_ = s.store.Mutate(func(st *store.State) error {
		st.FamilyJTIs[family] = append(st.FamilyJTIs[family], jti)
		return nil
	})
}

// RevokeToken 撤销单个刷新令牌及其所在链，并撤销关联的访问令牌（登出场景）。
func (s *Service) RevokeToken(token string) error {
	now := s.now()
	return s.store.Mutate(func(st *store.State) error {
		node, ok := st.RefreshNodes[token]
		if !ok {
			return internal.NewE(internal.CodeInvalidGrant, "unknown refresh token")
		}
		revokeFamilyLocked(st, node.FamilyID, now, "manual_revoke")
		return nil
	})
}

func revokeFamilyLocked(st *store.State, family string, now time.Time, kind string) {
	st.Families[family] = true
	for _, n := range st.RefreshNodes {
		if n.FamilyID == family {
			n.Revoked = true
		}
	}
	revokeFamilyJTIs(st, family, now)
	st.Audit = append(st.Audit, store.Event{
		Time:   now,
		Kind:   kind,
		Detail: "family=" + family,
	})
}

// RevokeAccessJTI 显式撤销一个访问令牌（按 jti）。
func (s *Service) RevokeFamily(family string) {
	now := s.now()
	_ = s.store.Mutate(func(st *store.State) error {
		if st.Families[family] {
			return nil
		}
		revokeFamilyLocked(st, family, now, "logout_revoke")
		return nil
	})
}

func (s *Service) RevokeAccessJTI(jti string) {
	now := s.now()
	_ = s.store.Mutate(func(st *store.State) error {
		st.RevokedJTI[jti] = now
		st.Audit = append(st.Audit, store.Event{
			Time:   now,
			Kind:   "access_revoked",
			Detail: "jti=" + jti,
		})
		return nil
	})
}

// IsAccessRevoked 判断访问令牌 jti 是否已撤销。
func (s *Service) IsAccessRevoked(jti string) bool {
	revoked := false
	s.store.View(func(st *store.State) {
		_, revoked = st.RevokedJTI[jti]
	})
	return revoked
}

// AuditEvents 返回持久化的审计事件副本。
func (s *Service) AuditEvents() []store.Event {
	return s.store.AuditEvents()
}

func randID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
