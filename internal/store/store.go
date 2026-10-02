// Package store 负责服务状态的持久化：签名密钥、刷新令牌链、
// 访问令牌撤销清单以及安全审计事件。采用"整文件原子替换"，
// 保证进程重启后已撤销/已换出的令牌不会复活。
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Key 是一把 HMAC 签名密钥。
type Key struct {
	ID        string    `json:"id"`
	Secret    []byte    `json:"secret"`
	CreatedAt time.Time `json:"created_at"`
	RotatedAt time.Time `json:"rotated_at,omitempty"` // 非零表示已被新密钥替换
}

// Active 返回该密钥是否仍是当前签发密钥。
func (k Key) Active() bool { return k.RotatedAt.IsZero() }

// RefreshNode 是刷新令牌链上的一个节点。
type RefreshNode struct {
	Token     string    `json:"token"`
	FamilyID  string    `json:"family_id"`
	Subject   string    `json:"subject"`
	ClientID  string    `json:"client_id"`
	JTI       string    `json:"jti"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	RotatedAt time.Time `json:"rotated_at,omitempty"`
	Revoked   bool      `json:"revoked,omitempty"`
}

// Event 是一条安全审计记录（刷新令牌复用、撤销等）。
type Event struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail"`
}

// State 是落盘的完整状态快照。
type State struct {
	Keys          []Key                   `json:"keys"`
	RefreshNodes  map[string]*RefreshNode `json:"refresh_nodes"`
	Families      map[string]bool         `json:"revoked_families"`
	RevokedJTI    map[string]time.Time    `json:"revoked_jti"`
	FamilySubject map[string]string       `json:"family_subject"`
	FamilyJTIs    map[string][]string     `json:"family_jtis"`
	Audit         []Event                 `json:"audit"`
}

// Store 在内存状态之上加锁并原子落盘。
type Store struct {
	path string
	mu   sync.Mutex
	st   State
}

// New 创建/打开状态文件。文件不存在时初始化一把新密钥。
func New(path string) (*Store, error) {
	s := &Store{path: path, st: State{
		RefreshNodes:  map[string]*RefreshNode{},
		Families:      map[string]bool{},
		RevokedJTI:    map[string]time.Time{},
		FamilySubject: map[string]string{},
		FamilyJTIs:    map[string][]string{},
	}}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &s.st); err != nil {
			return nil, err
		}
		if s.st.RefreshNodes == nil {
			s.st.RefreshNodes = map[string]*RefreshNode{}
		}
		if s.st.Families == nil {
			s.st.Families = map[string]bool{}
		}
		if s.st.RevokedJTI == nil {
			s.st.RevokedJTI = map[string]time.Time{}
		}
		if s.st.FamilySubject == nil {
			s.st.FamilySubject = map[string]string{}
		}
		if s.st.FamilyJTIs == nil {
			s.st.FamilyJTIs = map[string][]string{}
		}
	case errors.Is(err, os.ErrNotExist):
		k, err := newKey(time.Now())
		if err != nil {
			return nil, err
		}
		s.st.Keys = []Key{k}
		if err := s.persistLocked(); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return s, nil
}

func newKey(now time.Time) (Key, error) {
	sec := make([]byte, 32)
	if _, err := rand.Read(sec); err != nil {
		return Key{}, err
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return Key{}, err
	}
	return Key{ID: hex.EncodeToString(id), Secret: sec, CreatedAt: now}, nil
}

// Mutate 在持锁状态下读写状态，结束后原子落盘。
func (s *Store) Mutate(fn func(st *State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.st); err != nil {
		return err
	}
	return s.persistLocked()
}

// View 在持锁状态下只读快照。
func (s *Store) View(fn func(st *State)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.st)
}

// NewKey 生成并保存一把新密钥，同时把当前 active 密钥标记为已轮换。
func (s *Store) NewKey(now time.Time) (Key, error) {
	k, err := newKey(now)
	if err != nil {
		return Key{}, err
	}
	err = s.Mutate(func(st *State) error {
		for i := range st.Keys {
			if st.Keys[i].Active() {
				st.Keys[i].RotatedAt = now
			}
		}
		st.Keys = append(st.Keys, k)
		return nil
	})
	return k, err
}

// Audit 追加一条审计事件并落盘。
func (s *Store) Audit(kind, detail string, now time.Time) {
	_ = s.Mutate(func(st *State) error {
		st.Audit = append(st.Audit, Event{Time: now, Kind: kind, Detail: detail})
		return nil
	})
}

// AuditEvents 返回审计记录副本。
func (s *Store) AuditEvents() []Event {
	var out []Event
	s.View(func(st *State) {
		out = append(out, st.Audit...)
	})
	return out
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// RandomToken 生成一个高熵随机令牌字符串。
func RandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
