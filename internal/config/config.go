package config

import (
	"encoding/json"
	"os"
	"time"
)

// Duration 包装 time.Duration，使配置文件里可以直接写 "15m" 这样的字符串。
type Duration time.Duration

func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*d = Duration(n)
	return nil
}

// Client 描述一个被允许接入的本地客户端。
type Client struct {
	ID           string   `json:"id"`
	Secret       string   `json:"secret"`        // 本地演示用；confidential 客户端需要
	RedirectURIs []string `json:"redirect_uris"` // 必须精确匹配
}

// User 是内置的本地账号（不接任何外部账号体系）。
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Config 是服务的全部可配置项。
type Config struct {
	ListenAddr string `json:"listen_addr"`
	Issuer     string `json:"issuer"`
	Audience   string `json:"audience"`

	// 数据文件：刷新令牌链 / 撤销状态 / 当前密钥都持久化在这里。
	DataFile string `json:"data_file"`

	CodeTTL         Duration `json:"code_ttl"`
	AccessTokenTTL  Duration `json:"access_token_ttl"`
	RefreshTokenTTL Duration `json:"refresh_token_ttl"`
	ClockSkewLeeway Duration `json:"clock_skew_leeway"`

	// RotateInterval: 每隔多久生成一把新签名密钥（0 表示不自动轮换）。
	RotateInterval Duration `json:"rotate_interval"`
	// KeyGraceWindow: 旧密钥签发的令牌在轮换后多久内仍可校验通过。
	KeyGraceWindow Duration `json:"key_grace_window"`

	Clients []Client `json:"clients"`
	Users   []User   `json:"users"`
}

// Default 返回一份适合本地手工演示的默认配置。
func Default() Config {
	return Config{
		ListenAddr:      "127.0.0.1:8080",
		Issuer:          "local-oauth",
		Audience:        "local-services",
		DataFile:        "data/oauth-state.json",
		CodeTTL:         Duration(2 * time.Minute),
		AccessTokenTTL:  Duration(15 * time.Minute),
		RefreshTokenTTL: Duration(24 * time.Hour),
		ClockSkewLeeway: Duration(60 * time.Second),
		RotateInterval:  Duration(0),
		KeyGraceWindow:  Duration(24 * time.Hour),
		Clients: []Client{
			{
				ID:           "local-cli",
				Secret:       "local-secret",
				RedirectURIs: []string{"http://127.0.0.1:9999/callback"},
			},
		},
		Users: []User{
			{Username: "alice", Password: "password123"},
		},
	}
}

// Load 从 JSON 文件加载配置，文件不存在时返回默认配置。
func Load(path string) (Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// ClientByID 查找客户端。
func (c Config) ClientByID(id string) (Client, bool) {
	for _, cl := range c.Clients {
		if cl.ID == id {
			return cl, true
		}
	}
	return Client{}, false
}

// CheckUser 校验本地用户名密码。
func (c Config) CheckUser(username, password string) bool {
	for _, u := range c.Users {
		if u.Username == username && u.Password == password {
			return true
		}
	}
	return false
}

// HasRedirect 判断回调地址是否为该客户端注册过的地址。
func (cl Client) HasRedirect(uri string) bool {
	for _, r := range cl.RedirectURIs {
		if r == uri {
			return true
		}
	}
	return false
}
