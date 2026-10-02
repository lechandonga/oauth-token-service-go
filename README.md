# 本地身份认证与令牌服务（Go）

一个只在本机回环地址运行、**仅依赖 Go 标准库**的 OAuth 风格身份认证与令牌服务。
同机的其他服务可以通过它完成登录、换取访问令牌、校验令牌，以及刷新/撤销令牌。
不接入任何外部账号体系，账号与客户端都写在本地配置文件中。

- Module 与 Go 版本保持 `go.mod` 原样，未引入任何第三方依赖。
- 授权码：Authorization Code + PKCE（S256），一次性、短时效。
- 访问令牌：HS256 JWT（HMAC-SHA256），支持密钥轮换宽限窗口与时钟偏差容忍。
- 刷新令牌：一次性轮换（rotation），复用即整条令牌链撤销并写审计。
- 持久化：密钥、刷新令牌链、访问令牌撤销清单、审计日志全部落盘，重启状态不丢。

## 目录结构

| 路径 | 说明 |
| --- | --- |
| `cmd/server` | 本地服务启动入口 |
| `cmd/demo` | 一键走完整条流程的本地演示入口 |
| `internal/config` | 配置加载与默认值 |
| `internal/authcode` | 授权码签发/兑换、PKCE 校验 |
| `internal/token` | 访问令牌签发/校验（HS256、轮换、leeway） |
| `internal/refresh` | 刷新令牌轮换、复用检测、撤销 |
| `internal/store` | 状态持久化（原子写 JSON 文件） |
| `internal/server` | HTTP 路由与参数校验 |
| `configs/config.json` | 示例配置 |

## 协议流程

### 1. 授权码 + PKCE 登录

1. 客户端生成随机 `code_verifier`，计算 `code_challenge = BASE64URL(SHA256(verifier))`。
2. 浏览器打开：
   ```
   GET /authorize?response_type=code
       &client_id=local-cli
       &redirect_uri=http://127.0.0.1:9999/callback
       &code_challenge=<challenge>&state=<state>
   ```
   服务端先校验 `client_id` 与 `redirect_uri`（必须与注册值精确匹配），
   不合规直接拒绝，不会展示登录页、不会下发授权码。
3. 用户在本地登录页输入账号密码（默认 `alice / password123`）。
4. 登录成功后 302 回调：`redirect_uri?code=<授权码>&state=<state>`。
5. 客户端用 Basic Auth（`client_id:secret`）兑换：
   ```
   POST /token
   grant_type=authorization_code
   code=<授权码>&redirect_uri=<同一回调>&code_verifier=<verifier>
   ```
   返回 `access_token`、`refresh_token`、`expires_in`、`jti`。

授权码安全语义：

- 一次性：兑换成功即消费，重复使用返回 `invalid_grant`。
- 短时效：超过 `code_ttl` 返回 `code_expired`。
- PKCE：`code_verifier` 与 `code_challenge` 不符返回 `pkce_verifier_mismatch`；
  校验失败不消费授权码，客户端可更正 verifier 后重试。
- 参数绑定：兑换时 `client_id` / `redirect_uri` 与签发时不一致返回 `params_tampered`。
- 并发：兑换全程持锁，多个并发请求只有一个成功，其余得到明确失败码。

### 2. 访问令牌校验

```
POST /verify
Authorization: Bearer <access_token>
# 或 Body: {"token": "<access_token>"}
```

成功返回 `{"active": true, "subject": ..., "jti": ..., ...}`。
失败原因码可区分：

| 错误码 | 含义 |
| --- | --- |
| `malformed_token` | 不是合法 JWT / 声明无法解析 |
| `bad_signature` | 签名不匹配、alg 不受支持，或签名密钥已过宽限窗口 |
| `token_expired` | 已过期（超出时钟偏差容忍） |
| `invalid_issuer` | 签发方与本服务不一致 |
| `invalid_audience` | 受众不匹配 |
| `token_revoked` | 令牌已被登出/撤销 |

说明：校验接口只返回稳定的原因码与通用描述，不会把 base64/HMAC 等
底层加解密错误文本透传给调用方。

时钟偏差：校验时对 `exp`/`iat` 应用 `clock_skew_leeway`（默认 60s），
校验方时钟轻微快慢不会误杀有效令牌。

### 3. 刷新令牌轮换

```
POST /token
grant_type=refresh_token&refresh_token=<旧令牌>
```

- 每次刷新都换发一个**新的**刷新令牌，旧令牌立即标记为已轮换。
- 已轮换的旧令牌再次出现（典型的令牌失窃重放）会：
  1. 立即撤销整条令牌链（family），链上所有刷新令牌失效；
  2. 撤销该链上签发过的全部访问令牌（按 jti）；
  3. 写入 `refresh_reuse_detected` 审计记录；
  4. 返回 `refresh_reuse_detected`，后续使用链上任一令牌返回 `invalid_grant`。
- 并发刷新同一令牌：只有一个请求成功，其余得到明确失败。

### 4. 撤销与登出

- `POST /revoke`（Basic Auth）：`refresh_token=<令牌>`，撤销整条链与关联访问令牌。
- `POST /logout`（Bearer 访问令牌）：撤销该访问令牌及其所属刷新链。

撤销状态随每次变更原子落盘，进程重启后已撤销/已换出的令牌不会复活。

## 密钥与令牌生命周期

- 签名密钥为 32 字节随机 HMAC 密钥，首次启动自动生成，保存在数据文件中。
- 当前用于签发的密钥为 active；轮换时旧密钥记录 `rotated_at`。
- 旧密钥在 `key_grace_window`（默认 24h）内仍可校验其历史令牌；
  超过窗口，旧密钥签发的令牌以 `bad_signature` 明确拒绝。
- 手动立即轮换：`POST /admin/rotate`（返回新的 `active_key_id`）。
- 自动轮换：把 `rotate_interval` 设为非 0（如 `"168h"`），服务端定时轮换。
- 访问令牌有效期 `access_token_ttl`（默认 15m）；
  刷新令牌有效期 `refresh_token_ttl`（默认 24h），每次轮换顺延。
- 授权码仅保存在内存，有效期 `code_ttl`（默认 2m），重启丢失不影响安全语义。

## 可配置项（`configs/config.json`）

| 字段 | 含义 | 默认 |
| --- | --- | --- |
| `listen_addr` | 监听地址（建议只绑回环） | `127.0.0.1:8080` |
| `issuer` / `audience` | 令牌 `iss` / `aud` 校验值 | `local-oauth` / `local-services` |
| `data_file` | 状态持久化文件 | `data/oauth-state.json` |
| `code_ttl` | 授权码有效期 | `2m` |
| `access_token_ttl` | 访问令牌有效期 | `15m` |
| `refresh_token_ttl` | 刷新令牌有效期 | `24h` |
| `clock_skew_leeway` | 校验容忍的时钟偏差 | `60s` |
| `rotate_interval` | 自动密钥轮换周期，`0s` 关闭 | `0s` |
| `key_grace_window` | 旧密钥宽限窗口 | `24h` |
| `clients[]` | 允许的客户端：`id` / `secret` / `redirect_uris` | 内置 `local-cli` |
| `users[]` | 本地账号：`username` / `password` | 内置 `alice` |

时长字段使用 Go duration 字符串（`"30s"`、`"15m"`、`"24h"`）。

## 本地启动与手工验证

需要 Go 1.25+（仓库在 Go 1.26 上验证）。

### 一键演示（最快走完整流程）

```bash
go run ./cmd/demo
```

演示在临时目录中起服务并依次验证：登录表单、错误密码、非法回调、
授权码兑换与重放、PKCE 失败、令牌校验、签名篡改、刷新轮换、
复用撤销+审计、登出失效、重启恢复、时钟偏差、密钥轮换宽限窗口、令牌过期，
每个场景打印 `PASS/FAIL`。

### 启动常驻服务

```bash
go run ./cmd/server -config configs/config.json
```

手工走流程（另开终端）：

```bash
# 1) 生成 PKCE 对（示例：固定 verifier）
verifier="DB6Mx2A5N-8g-6oQ7jZ9xQ0pR2sT3uV4wX5yZ6a7b8C"
challenge=$(printf '%s' "$verifier" | openssl dgst -binary -sha256 | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# 2) 浏览器打开登录（用默认账号 alice / password123）
xdg-open "http://127.0.0.1:8080/authorize?response_type=code&client_id=local-cli&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcallback&code_challenge=$challenge&state=demo"
# 登录后浏览器会跳转到回调地址，从地址栏复制 code= 参数

# 3) 用授权码换令牌
curl -s -u local-cli:local-secret -X POST http://127.0.0.1:8080/token \
  -d grant_type=authorization_code \
  --data-urlencode code=<上一步的code> \
  --data-urlencode redirect_uri=http://127.0.0.1:9999/callback \
  --data-urlencode code_verifier="$verifier"

# 4) 校验访问令牌
curl -s -X POST http://127.0.0.1:8080/verify -H "Authorization: Bearer <access_token>"

# 5) 刷新
curl -s -u local-cli:local-secret -X POST http://127.0.0.1:8080/token \
  -d grant_type=refresh_token --data-urlencode refresh_token=<refresh_token>

# 6) 登出 / 撤销 / 轮换密钥 / 查审计
curl -s -X POST http://127.0.0.1:8080/logout -H "Authorization: Bearer <access_token>"
curl -s -u local-cli:local-secret -X POST http://127.0.0.1:8080/revoke --data-urlencode refresh_token=<refresh_token>
curl -s -X POST http://127.0.0.1:8080/admin/rotate
curl -s http://127.0.0.1:8080/audit
```

## 运行测试

```bash
# 普通测试
go test ./...

# 竞态检测（要求本机有 C 工具链，CGO 默认开启）
CGO_ENABLED=1 go test -race ./...

# 查看每个场景/用例与结果的详细日志
CGO_ENABLED=1 go test -race -v ./...
```

测试覆盖：授权码重放、过期、参数篡改、PKCE 失败、并发兑换、
令牌过期/签名篡改/iss/aud、时钟偏差、密钥轮换宽限窗口、
刷新令牌轮换、复用整链撤销与审计、主动撤销、重启状态恢复、并发刷新。
日志以 `[场景] ... 用例=... 结果=PASS/FAIL (got=.. want=..)` 的形式输出。

## 安全边界（本地用途）

- 服务只应绑定回环地址；账号、客户端密钥仅用于本机演示，请勿用于生产。
- 数据文件包含 HMAC 密钥与刷新令牌，默认以 `0600` 权限写入。
- 传输仅限本机回环；如需跨机使用请自行在前面加 TLS 反向代理并重新评估威胁模型。
