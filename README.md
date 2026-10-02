# Local OAuth Token Service (Go, stdlib only)

A self-contained identity & token service for services running on the same
machine. It supports the OAuth 2.0 authorization-code grant with PKCE,
signed access tokens with rotating signing keys, and rotating refresh tokens
with reuse detection. Everything runs locally: there is no external account
system, no network egress and **no third-party dependencies** (Go standard
library only).

## Components

| Path | Responsibility |
| --- | --- |
| `internal/authcode` | One-time, short-lived authorization codes bound to client / redirect URI / PKCE challenge (S256, RFC 7636) |
| `internal/token` | HS256 compact access tokens (JWT-style) and the versioned signing key ring with rotation grace window |
| `internal/store` | Durable sessions, refresh-token rotation chains and the audit trail (atomic JSON files) |
| `internal/oauth` | Service facade + HTTP endpoints (`/authorize`, `/token`, `/introspect`, `/revoke`, `/logout`, `/metadata`) |
| `cmd/server` | Real local HTTP server entry point |
| `cmd/demo` | In-process end-to-end walkthrough of every happy/negative scenario |

## Protocol flow

1. **Authorize** — the client generates a PKCE `code_verifier`, sends
   `code_challenge = BASE64URL(SHA256(verifier))` to `GET /authorize`, the
   user completes the local login form, and the browser is redirected back to
   the registered loopback `redirect_uri` with a one-time `code`.
2. **Exchange** — `POST /token` with `grant_type=authorization_code`, the
   code, the exact redirect URI, `client_id`, and the `code_verifier`. The
   service verifies PKCE, consumes the code exactly once, and returns an
   access token + refresh token.
3. **Use** — other local services send `Authorization: Bearer <access_token>`
   and the resource server checks it via `GET /introspect` (or verifies it
   directly with the shared key).
4. **Refresh** — `POST /token` with `grant_type=refresh_token`. The old
   refresh token is consumed immediately and a brand-new one returned.
5. **Revoke / logout** — `POST /revoke` (RFC 7009) revokes the whole token
   family; `POST /logout` (Bearer access token) kills the session.

### Failure reasons are distinguishable

Authorization-code exchange returns stable error codes:

| Code | Trigger |
| --- | --- |
| `invalid_code` | code was never issued |
| `code_expired` | code past its short TTL |
| `code_replayed` | one-time code presented more than once |
| `pkce_mismatch` | `code_verifier` does not match the challenge |
| `parameter_mismatch` | `client_id` / `redirect_uri` differ from authorization |

Access-token verification returns: `malformed_token`, `invalid_signature`,
`no_trusted_key`, `token_expired`, `token_not_yet_valid`, `issuer_mismatch`,
`audience_mismatch`, or `invalid_grant` (session/family revoked).
Low-level cryptographic errors are never surfaced verbatim.

Authorization rejects `invalid_client`, `invalid_redirect_uri`,
`invalid_request`, `unsupported_response_type`, `access_denied` **before** a
code is issued, and an invalid client/redirect never causes a redirect back to
the untrusted URI.

## Key & token lifecycle

- **Authorization codes**: random 256-bit, TTL default 60s, one-time. Any
  failed presentation (expired, bad PKCE, tampered parameters) also consumes
  the code; state is persisted so replays survive restarts.
- **Access tokens**: HS256, claims `iss/sub/aud/iat/nbf/exp/jti/sid/scope`.
  Verification tolerates a configurable clock-skew leeway (default 30s).
- **Signing keys**: a current key plus retired keys. `RotateKeys` (or
  `--rotate-keys` at startup) promotes a new key; the old key keeps verifying
  existing tokens for the grace window (default 24h, should be >= max access
  TTL), after which its tokens fail with `no_trusted_key`. Keys persist under
  the data directory, so restarts do not invalidate outstanding tokens.
- **Refresh tokens**: opaque 256-bit random strings; only SHA-256 hashes are
  stored. Every refresh rotates the token (rolling TTL). Presenting an
  already-rotated token is treated as theft: the **entire family** (session
  plus all access/refresh tokens) is revoked immediately and an audit event
  is written.
- **Logout / revocation**: session-level state is checked on every access
  token introspection, so revocation takes effect immediately without waiting
  for token expiry.
- **Durability**: all state is written atomically (temp file + rename, 0600)
  to JSON files. Revoked/rotated tokens do not resurrect after a restart.

## Endpoints

| Method & path | Purpose |
| --- | --- |
| `GET /healthz` | liveness |
| `GET /metadata` | endpoint discovery document |
| `GET /authorize` | validated login form |
| `POST /authorize` | authenticate locally, 303 redirect with `code` |
| `POST /token` | `authorization_code` or `refresh_token` grants |
| `GET /introspect` | verify `Bearer` access token (`{"active":true,...}`) |
| `POST /revoke` | revoke refresh token family (`token=...`) |
| `POST /logout` | revoke session of the presented Bearer token |

The server binds loopback only. Defaults: client `local-cli` with callback
`http://127.0.0.1:9876/callback`, local user `demo` / `demo-pass`.

## Run locally

```bash
# one command walks the whole protocol and prints every scenario/result
go run ./cmd/demo

# real HTTP service
go run ./cmd/server --addr 127.0.0.1:8080 --data-dir ./.local-oauth-data
```

### Manual verification with curl

```bash
# 1. PKCE pair
verifier=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
challenge=$(printf %s "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# 2. login + authorize (the server redirects to the callback with ?code=...)
curl -i -X POST http://127.0.0.1:8080/authorize \
  --data-urlencode response_type=code \
  --data-urlencode client_id=local-cli \
  --data-urlencode redirect_uri=http://127.0.0.1:9876/callback \
  --data-urlencode state=xyz --data-urlencode code_challenge="$challenge" \
  --data-urlencode code_challenge_method=S256 \
  --data-urlencode username=demo --data-urlencode password=demo-pass

# 3. exchange code for tokens
curl -s -X POST http://127.0.0.1:8080/token \
  --data-urlencode grant_type=authorization_code \
  --data-urlencode code="$CODE" \
  --data-urlencode redirect_uri=http://127.0.0.1:9876/callback \
  --data-urlencode client_id=local-cli \
  --data-urlencode code_verifier="$verifier"

# 4. introspect
curl -s -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:8080/introspect

# 5. rotate refresh token
curl -s -X POST http://127.0.0.1:8080/token \
  --data-urlencode grant_type=refresh_token \
  --data-urlencode refresh_token="$REFRESH_TOKEN"

# 6. logout (kills access + refresh tokens immediately)
curl -s -X POST -H "Authorization: Bearer $ACCESS_TOKEN" http://127.0.0.1:8080/logout
```

Key rotation demonstration:

```bash
go run ./cmd/server --rotate-keys --key-grace 1m   # old key valid 1 minute
```

## Configuration

`cmd/server` flags (all optional):

| Flag | Default | Meaning |
| --- | --- | --- |
| `--addr` | `127.0.0.1:8080` | loopback listen address |
| `--data-dir` | `./.local-oauth-data` | durable state directory (`authcodes.json`, `keys.json`, `sessions.json`) |
| `--issuer` | `http://127.0.0.1:8080` | access token `iss` |
| `--audience` | `local-resource-api` | required access token `aud` |
| `--access-ttl` | `15m` | access token lifetime |
| `--refresh-ttl` | `168h` | refresh token lifetime (reset per rotation) |
| `--code-ttl` | `60s` | authorization code lifetime |
| `--leeway` | `30s` | clock-skew tolerance for exp/nbf checks |
| `--key-grace` | `24h` | grace window for retired signing keys |
| `--rotate-keys` | `false` | rotate the signing key at startup |

When embedding `internal/oauth`, `oauth.Config` additionally accepts
`Clients map[string][]string`, `Users map[string]string`, and an injectable
`Clock func() time.Time` (used by tests).

## Tests

```bash
go test ./... -race -v
```

Coverage (each scenario logs its cases and results):

- authorization code: valid PKCE exchange, replay, 16-way concurrent exchange
  (exactly one winner), expiry, wrong verifier, tampered client/redirect,
  unknown code, client/redirect registration validation, restart persistence;
- access tokens: sign/verify round trip, clock skew within/beyond leeway,
  issuer/audience mismatch, tampered and malformed tokens (no crypto-leak),
  rotation grace window acceptance and post-window rejection, key persistence,
  concurrent sign/verify under `-race`;
- refresh/sessions: rotation, reuse-triggered whole-family revocation,
  logout, RFC 7009 revocation, expiry, unknown tokens, restart recovery,
  24-way concurrent rotation of one token (exactly one winner) and concurrent
  rotation of distinct sessions.

## Security notes

- Loopback bind only; redirect URIs must be `http(s)` on `localhost` /
  `127.0.0.1` / `[::1]` and registered exactly per client.
- Only PKCE `S256` is accepted; plain challenges are refused.
- Refresh tokens are stored only as SHA-256 hashes; state files are 0600.
- HMAC signatures are compared in constant time; secrets are 256-bit random.
