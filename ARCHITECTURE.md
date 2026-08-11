# Authentication Platform — Phase 0 Architecture Proposal

**Status:** approved (v2) — plus consumer JWT bridge delta (v2.1)
**Date:** 2026-08-10
**Scope:** V1 per build specification (identity, sessions, verification, recovery, MFA foundation, security events, rate limiting, versioned API) + React/TypeScript frontend.
**Consumer rule:** this is a standalone platform. Zero references to any consumer-project name anywhere in the repository (grep-checked before every commit).

---

## 1. Executive summary

A standalone auth platform with a versioned REST API (`/api/v1`), consumed by frontends/backends over HTTP. Layering is strictly `Controller → Application Service → Domain → Repository → DB` (R-30); controllers never touch the DB. Six domain modules (identity, authentication, sessions, verification, mfa, security) depend only downward onto `infrastructure`/`shared`, never sideways into each other's internals (R-1, §3). Authorization is explicitly out of scope — the platform ships session authentication only, with an `Authorizer` seam reserved for consumers.

Decisions locked in this document:

- **CSRF (R-18):** `SameSite=Strict` cookies **+** fail-closed Origin/Referer verification (state-changing requests without a valid origin are rejected). No double-submit token. Rationale in §6.3.
- **Session fixation (R-10):** no pre-login cookie is ever issued, so there is nothing to fixate or upgrade. A fresh CSPRNG session secret is issued only after full authentication (including MFA when enrolled).
- **MFA (R-25):** password success + MFA enrolled → short-lived (5 min) single-purpose `MFA_PENDING` token → TOTP/recovery code → real session.
- **Brute force (R-20/R-21):** per-(email, IP) failed-attempt limiter + persisted time-boxed account lock (`locked_until`), plus IP-level limiters, with distinct security event types.
- **Enumeration resistance (R-12):** dummy-Argon2id verify on unknown-user logins; uniform response shapes on signup/forgot/verify; distinction lives only in the internal security-event log.
- **Service integration:** `POST /auth/introspect` (service-key-gated) lets consumer backends validate forwarded session secrets over the API — no shared DB, no shared code (§8.1).
- **Consumer JWT bridge:** `POST /auth/tokens` mints short-lived (15 min) RS256 access tokens from a validated session. Consumers whose APIs authenticate with Bearer tokens (no cookies) get verifiable identity claims without sharing our DB or session store (§5.1, §8.2).
- **Config (R-35/R-36):** zod-validated at boot; missing required secrets crash startup; rate-limiter backend, retention window, key rotation, and DB pool sizing are all config-driven. No silent insecure defaults.

---

## 2. Tech stack

| Layer | Choice | Rationale |
|---|---|---|
| Runtime | Node.js 24 + TypeScript (strict) | verified available (v24.18.0) |
| HTTP framework | **Express 5** | async handlers forward rejections to error middleware natively |
| DB | PostgreSQL 16 + `pg` | relational integrity for tokens/sessions/events |
| Query/migrations | **Kysely** (typed SQL builder + migration runner) | type-safe repositories, no ORM magic |
| Validation | **zod** | schemas double as request validation + config validation |
| Password hashing | **argon2** (node-argon2), Argon2id only | R-7; params centralized in `infrastructure/crypto` (R-8) |
| TOTP | **otplib** (30 s, 6 digits, SHA-1) | standard |
| MFA secret at rest | AES-256-GCM via `node:crypto`; **versioned key list** (`MFA_ENCRYPTION_KEYS=v2:base64...,v1:base64...`), encrypt with newest, lazy re-encrypt on read | R-23 + rotation |
| IDs | hand-rolled ULID helper (26-char Crockford base32, no dep) | R-3: `usr_…`/`sess_…`/`tok_…`/`mfac_…`/`rc_…` |
| Email | `EmailProvider` interface (`ConsoleEmailProvider` dev / `SmtpEmailProvider` nodemailer) consumed via a **DB outbox + in-process worker** (retry/backoff) — never inline on the request path | swappable; SMTP outages don't break signup/reset |
| Consumer JWTs | **jose** (RS256) | minted from sessions, 15-min TTL, no secrets in claims (§5.1) |
| Rate limiting | custom `RateLimiter` interface with **two shipped adapters**: `InMemoryRateLimiter` (dev default) + `RedisRateLimiter` (prod, `ioredis`); backend selected by `RATE_LIMITER_BACKEND` config, prod requires redis (fail-fast) | R-20 pluggable backend; controls do not weaken under horizontal scaling |
| Logging | **pino** + pino-http with query-string-redacting serializers | R-19/R-27 |
| Security headers | **helmet** (CSP configured) + explicit HSTS | R-32 |
| Consumer auth middleware | `packages/session` — npm-workspace package: `requireSession({ apiBaseUrl, serviceApiKey })` (cookie → introspect) and `verifyJwt({ publicKey, issuer, audience })` (Bearer → jose verify) Express middlewares + typed client | phase 7 |
| Tests | **vitest** + **supertest**; test Postgres DB `auuth_test` | §21 |
| Frontend | React 18 + TypeScript + Vite + react-router-dom, plain CSS | lean; no secrets in storage (R-19) |
| CI | GitHub Actions: typecheck/lint/test with Postgres service, `npm audit`, gitleaks | R-37 |
| Workspaces | npm workspaces: `apps/api`, `apps/web`, `packages/session` | monorepo; consumers never share DB code |

Express 5 + TS strict + zod ⇒ uniform validation and error propagation; no `any`, no unvalidated input reaches a service.

---

## 3. Repository layout

```
auuth/
├── apps/
│   ├── api/                          # Express backend
│   │   ├── src/
│   │   │   ├── app/                  # routes, middleware, bootstrap
│   │   │   │   ├── routes/           # one router per module (auth.ts, sessions.ts, mfa.ts, me.ts)
│   │   │   │   ├── middleware/       # requestId, securityHeaders, originCheck, authenticate, rateLimit, errorHandler
│   │   │   │   └── bootstrap.ts      # config validate → db connect → migrate → listen
│   │   │   ├── modules/
│   │   │   │   ├── identity/         # UserService, AccountStatePolicy, EmailNormalizer, UserRepository
│   │   │   │   ├── authentication/   # AuthenticationService (login/logout pipeline), AuthMethod types
│   │   │   │   ├── sessions/         # SessionService, SessionRepository
│   │   │   │   ├── verification/     # VerificationService, TokenRepository
│   │   │   │   ├── mfa/              # MfaService, Totp, MfaRepository (credentials + recovery codes)
│   │   │   │   └── security/         # RateLimiter (iface+inmem), BruteForceGuard, SecurityEventService, SecurityEventRepository
│   │   │   ├── infrastructure/       # db (pg+kysely+migrations), email, crypto (argon2/tokens/aes-gcm/ulid/jwt-rs256), logging, config
│   │   │   └── shared/               # AppError + error codes, validation helpers, time utils
│   │   ├── migrations/               # kysely TS migration files
│   │   ├── tests/                    # unit / integration / security / e2e-flows
│   │   ├── openapi.yaml              # R-31
│   │   └── .env.example
│   └── web/                          # React frontend (Vite)
│       └── src/                      # pages/, components/, api/, auth/
├── packages/session/                 # phase 7: consumer-facing middleware + client (cookie introspect + JWT verify)
├── docker-compose.yml                # postgres for dev/test
├── .github/workflows/ci.yml          # R-37
├── .gitleaks.toml
└── ARCHITECTURE.md
```

**Module rules:** a module may import `infrastructure` and `shared` freely; cross-module access only via the target module's public service interface (e.g. `authentication` calls `SessionService`, `TokenService`, `MfaService`, `SecurityEventService` — never their repositories). Repositories are the only code that touches the DB (R-30).
---

## 4. Data model (PostgreSQL DDL)

All timestamps `TIMESTAMPTZ`. `security_events.id` is `BIGSERIAL` but internal-only — never exposed (R-3 applies to public-facing IDs).

```sql
CREATE TABLE users (
  id                TEXT PRIMARY KEY,            -- usr_<26-char ULID>
  email             TEXT NOT NULL UNIQUE,        -- normalized: lowercase, trimmed, punycode'd
  password_hash     TEXT NOT NULL,               -- argon2id encoded string; never read by any API
  first_name        TEXT,
  last_name         TEXT,
  status            TEXT NOT NULL DEFAULT 'PENDING_VERIFICATION'
                    CHECK (status IN ('PENDING_VERIFICATION','ACTIVE','SUSPENDED','LOCKED','DEACTIVATED')),
  email_verified_at TIMESTAMPTZ,
  locked_until      TIMESTAMPTZ,                 -- time-boxed brute-force lock (auto-clears)
  last_login_at     TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at        TIMESTAMPTZ                  -- soft delete
);

CREATE TABLE mfa_credentials (
  id                TEXT PRIMARY KEY,            -- mfac_<ulid>
  user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  method            TEXT NOT NULL,               -- 'totp' (future: 'webauthn', ...) — pluggable methods (R-22)
  secret_encrypted  TEXT NOT NULL,               -- base64(iv || authTag || ciphertext), AES-256-GCM
  key_version       INTEGER NOT NULL DEFAULT 1,  -- encryption key version used; enables rotation (§6.7)
  enabled_at        TIMESTAMPTZ,                 -- set only after first successful verification
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, method)
);

CREATE TABLE recovery_codes (
  id         TEXT PRIMARY KEY,                   -- rc_<ulid>
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  TEXT NOT NULL,                      -- sha256(raw code); codes shown once at enrollment (R-24)
  used_at    TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
  id           TEXT PRIMARY KEY,                 -- sess_<ulid> — safe identifier used in API URLs
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash   TEXT NOT NULL UNIQUE,             -- sha256(session secret); raw secret never stored (R-17)
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ NOT NULL,
  last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip_address   INET,                             -- retention: anonymized after RETENTION_DAYS (R-29)
  user_agent   TEXT,
  revoked_at   TIMESTAMPTZ
);
CREATE INDEX idx_sessions_user ON sessions (user_id);

CREATE TABLE tokens (
  id          TEXT PRIMARY KEY,                  -- tok_<ulid>
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL CHECK (kind IN ('EMAIL_VERIFICATION','PASSWORD_RESET','MFA_PENDING')),
  token_hash  TEXT NOT NULL UNIQUE,              -- sha256(raw token) (R-13)
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata    JSONB NOT NULL DEFAULT '{}'::jsonb -- e.g. MFA-pending context (ip, ua); whitelisted keys only
);

CREATE TABLE security_events (
  id             BIGSERIAL PRIMARY KEY,          -- internal only, never exposed
  event_type     TEXT NOT NULL,                  -- full set from §15
  user_id        TEXT REFERENCES users(id) ON DELETE SET NULL,
  actor          TEXT NOT NULL DEFAULT 'USER' CHECK (actor IN ('USER','SYSTEM')),
  ip_address     INET,                           -- retention: anonymized after RETENTION_DAYS
  user_agent     TEXT,
  correlation_id TEXT,                           -- ties to request logs
  metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
  occurred_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_events_user ON security_events (user_id, occurred_at DESC);
CREATE INDEX idx_events_type ON security_events (event_type, occurred_at DESC);
CREATE INDEX idx_events_time ON security_events (occurred_at DESC);

CREATE TABLE email_outbox (
  id              BIGSERIAL PRIMARY KEY,         -- internal only
  recipient       TEXT NOT NULL,
  subject         TEXT NOT NULL,
  body            TEXT NOT NULL,
  token_ref       TEXT,                          -- tok_<ulid> this email carries; traceability, never the raw token
  attempt_count   INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  sent_at         TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_outbox_due ON email_outbox (next_attempt_at) WHERE sent_at IS NULL;
```

Migrations are checked-in TS files run via `npm run migrate`; tests migrate `auuth_test` from scratch.
---

## 5. Session & cookie model

**Session secret flow (R-16/R-17):**

1. On full authentication success: `secret = randomBytes(32).toString('base64url')` — CSPRNG, issued server-side, never sent in any body.
2. `tokenHash = sha256(secret)` stored in `sessions`; a DB leak does not enable hijack.
3. Cookie value = the raw `secret`. Lookup = hash incoming cookie → single indexed query by `token_hash` (one query ⇒ no two-step timing leak).
4. API references sessions by `sessions.id` (safe identifier), never the secret.

**Cookie spec (R-16):**

```
Name: __Host-ap_session   (requires Secure + no Domain — modern hardening)
Value: <32-byte base64url secret>
HttpOnly: true
Secure: true            (always when COOKIE_SECURE=true; required in prod — R-33)
SameSite: Strict        (documented CSRF posture, §6.3)
Path: /
Max-Age: <= SESSION_EXPIRY (default 30 days)
```

**Session lifecycle:** `SESSION_CREATED` on issue; `last_used_at` touched on authenticated requests (write throttled to >=1 min); `SESSION_REVOKED` / `ALL_SESSIONS_REVOKED` on revocation; logout marks `revoked_at` server-side then clears the cookie. Password reset revokes **all** sessions (R-15). `change-password` revokes all sessions except the current one (documented deviation, §12).

**IDOR:** session revoke queries are scoped `WHERE id = $1 AND user_id = $2`; a foreign session id returns `404 NOT_FOUND` (no existence oracle).

### 5.1 Consumer access tokens (JWT bridge)

The session cookie is the platform's long-lived, revocable credential. Some consumers authenticate API-to-API with Bearer tokens and need verifiable claims (their middleware builds a tenant context from JWT claims, not from cookies). `POST /auth/tokens` (session-authenticated) bridges the two:

1. Request: valid session cookie → mint `RS256` JWT: `sub` (user id), `email`, `email_verified`, `status`, `iat`, `exp` (15 min, `JWT_ACCESS_TTL`), `iss` (`JWT_ISSUER`), `aud` (`JWT_AUDIENCE`), `jti` (ULID), `typ: "at+jwt"`. **No secrets, no session id, no internal metadata in claims.**
2. Consumers verify out-of-band with the platform's public key (`packages/session.verifyJwt`), then trust `sub`/`email`/`email_verified` — no round-trip per request, matching their "no sessions held in the API" constraint.
3. **No refresh tokens.** The cookie is the refresh: the frontend re-mints before expiry via the session cookie. 15-min TTL bounds the damage window of a stolen token; `aud`/`iss` pin usage; frontends hold the token in memory only (never localStorage — §9).
4. **Revocation stance:** tokens are stateless and not revocable; 15-min TTL makes this acceptable (documented, §11 #12). **Key rotation = config swap:** changing `JWT_PRIVATE_KEY` invalidates all outstanding tokens within ≤15 min — the natural kill-switch.
5. CSRF: minting is session-cookie-authenticated, so the fail-closed Origin/Referer check (§6.3) applies to `POST /auth/tokens` exactly like any other session endpoint.

---

## 6. Security posture decisions

### 6.1 Enumeration & timing (R-12)

- **Login:** unknown email → verify password against a precomputed **dummy Argon2id hash** (same params) so timing is dominated by the hash cost either way; response is always `INVALID_CREDENTIALS`. On *successful* verify, run `argon2.needsRehash(hash, currentParams)` and transparently rehash with current params if stale — so future cost-parameter upgrades apply to the whole user base, not just new signups.
- **Signup:** always respond `201 { message: "check your email" }`, even for an existing email (internal `USER_REGISTERED` / `DUPLICATE_SIGNUP_ATTEMPT` events only). No user id, no email echo.
- **Forgot-password / resend-verification:** always respond "if that account exists, an email was sent". No existence signal in body, status code, or timing (email-send is skipped for missing accounts but the response path is identical).
- **Verify-email / reset-password:** token errors collapse to one external shape `TOKEN_INVALID` (missing/used/expired/foreign), distinguished only in events.

### 6.2 Dummy-hash guarantee

Computed once at boot (`infrastructure/crypto`) with the same memory/time cost as real verifies, so a login for a non-existent user still spends ~300 ms in Argon2id.

### 6.3 CSRF (R-18) — chosen strategy, documented

**`SameSite=Strict` + Origin/Referer verification.**

- Consumers: (a) the first-party frontend (same origin in prod: Express serves the built SPA; Vite proxy in dev) and (b) future server-to-server consumers (no cookies — unaffected by CSRF rules).
- Strict prevents cookie attach on cross-site requests in modern browsers; the Origin/Referer check is defense-in-depth for older agents and sibling-domain requests.
- Double-submit token rejected: adds cookie+header coordination for no security gain given Strict + Origin check, and requires a non-httpOnly cookie unless carefully implemented.

Middleware (**fail-closed**): every state-changing request MUST carry an `Origin` or `Referer` header that is present in `ALLOWED_ORIGINS` (config; defaults `FRONTEND_URL` + `AUTH_BASE_URL`). Both headers absent → `403 INVALID_ORIGIN` — the check never passes open. Browsers always send at least one of the two on cross-site fetch/form submissions, so legitimate traffic is unaffected; non-browser clients that cannot send an origin are rejected from cookie-authenticated endpoints and belong on the service path (§8.1). `Host` is validated against configured hosts. GET/HEAD/OPTIONS are exempt from the origin check but not from rate limits. The service-key-gated introspect route (§8.1) is exempt from Origin enforcement and authenticates via key instead. The JWT-minting route `POST /auth/tokens` is session-authenticated and therefore **not** exempt — the same origin rules apply; the minted JWT itself is not a cookie and carries no CSRF surface (§5.1).

### 6.4 Session fixation (R-10)

V1 never issues a pre-auth cookie. Anonymous users have no session. A session is created exactly once per successful authentication; the MFA-pending stage also sets no cookie. Nothing can be "upgraded in place".

### 6.5 Password policy (R-9)

- min 12 chars, max 128 chars (DoS cap), no complexity rules.
- Breached-password check: local Top-10k blocklist (SHA-1 prefix k-anonymity matching, loaded at boot) behind `BreachedPasswordChecker` interface; `HibpRangeChecker` (range API) is the documented pluggable alternative. Ship with the local one — no external call at signup.

### 6.6 Brute force & lockout (R-20/R-21)

Thresholds (config-tunable, real numbers shipped):

| Target | Limit | Consequence |
|---|---|---|
| Login — per (email, IP) | 5 failed / 15 min | `ACCOUNT_LOCK`: time-boxed `locked_until = now + 15 min`; `AccountStatePolicy.canLogin` then blocks |
| Login — per IP (all attempts) | 20 / min | `RATE_LIMIT_EVENT`, HTTP 429 + `Retry-After` |
| Signup | 5 / hour / IP | 429 |
| Forgot-password | 5 / hour / (email, IP) | 429 |
| Resend verification | 3 / hour / email | 429 |
| Verify-email / reset-password | 10 / hour / IP | 429 |
| MFA verify | 5 failed / 15 min **per user** (resolved from the `MFA_PENDING` token record — not IP, so spreading guesses across tokens doesn't bypass) | pending token invalidated after 5 fails → re-login required; failure count persisted in token `metadata` (survives restarts) |
| Change-password | 5 / 15 min / IP | 429 |
| Introspect (service) | 600 / min per API key (+ IP) | 429 |

`BruteForceGuard` wraps login/change-password/MFA pipelines: counts failures via the `RateLimiter`, persists the account lock in the DB (`locked_until`, survives restarts), emits distinct `ACCOUNT_LOCK` / `RATE_LIMIT_EVENT` / `AUTH_FAILURE` events (R-21). A locked/suspended/deactivated account gets the same generic response as bad credentials; the *reason* exists only in the security-event log (R-5).

`SUSPENDED` / `DEACTIVATED` transitions are out-of-band (admin tooling is a non-goal; recorded via `SYSTEM`-actor events).

**Lockout-DoS trade-off (accepted risk, §11):** an attacker who knows a victim's email can deliberately trigger 5 failed logins and lock the account for 15 min — repeatedly. Accepted for V1 with a config-driven escalation seam: after N lockouts within a rolling window, the guard switches to a `CaptchaChallenger` requirement (pluggable interface, no-op in V1) or progressive delay instead of a hard lock. Escalation is designed but disabled by default; the decision is recorded in §11, not silently absent.

### 6.7 MFA (R-22–R-25)

- `AuthenticationMethod: Password | Totp | RecoveryCode` union type in `authentication`; the login pipeline iterates required methods — no if/else on the controller.
- **Enroll (authenticated session):** generate TOTP secret → encrypt AES-256-GCM with the **current key version** → store `mfa_credentials(secret_encrypted, key_version, enabled_at=NULL)` → return `otpauth://` URI, QR payload, and **10 recovery codes** (shown once). Recovery codes: `rc-XXXX-XXXX-XXXX`, SHA-256 hashed at rest, single-use.
- **Key rotation:** `MFA_ENCRYPTION_KEYS` is an ordered, versioned key list (`v2:base64...,v1:base64...`); new/rotated secrets encrypt with the newest key, decryption looks up the version recorded in `key_version`, and any row read under an old version is **lazily re-encrypted** with the newest key. Rotation never locks out enrolled users and needs no downtime or data migration.
- **Verify during enrollment:** correct TOTP → set `enabled_at`, emit `MFA_ENABLED`. A stale pending enrollment is overwritten by a new enroll (documented).
- **Login with MFA:** password ok + enrolled → create `MFA_PENDING` token (5 min, hashed, single-use, metadata carries ip/ua) → `200 { mfaRequired: true, mfaPendingToken }`. `/mfa/verify` accepts `mfaPendingToken` + `code` (or `recoveryCode`); success → real session cookie + `LOGIN_SUCCESS`. No cookie before this point (R-10).
- **Disable (authenticated):** requires a current valid TOTP code; deletes credential + recovery codes; emits `MFA_DISABLED`.
- The MFA-pending token is a short-lived capability token returned in the response body (documented deviation, §12) — hashed at rest, single-use, never logged.

### 6.8 Security events (R-26–R-28)

All event types from §15 recorded to `security_events` — a separate stream from pino request logs. Recording goes through `SecurityEventService.record(...)`, which enforces a **metadata whitelist** (pre-declared, non-secret keys only, e.g. `reason: 'bad_password'`) — a structural guarantee that no secret ever enters an event (R-27). Export seam: `SecurityEventExporter` interface (no-op in V1); a future outbox/webhook consumer attaches without touching the core (R-28). `correlation_id` ties events to request logs.

### 6.9 Errors & correlation (R-34)

- `AppError { code, message, status }`. Code list: `VALIDATION`, `INVALID_CREDENTIALS`, `TOKEN_INVALID`, `RATE_LIMITED`, `UNAUTHENTICATED`, `NOT_FOUND`, `CONFLICT`, `MFA_REQUIRED`, `MFA_INVALID`, `INVALID_ORIGIN`, `USER_DISABLED` (internal only), `INTERNAL`.
- Every response carries `X-Request-Id` (generated or forwarded); logs and events carry it. Client shape: `{ "error": { "code", "message", "requestId" } }`. No stack traces, no DB errors, no hashes, no secrets (R-11).
- 429 responses include `Retry-After`.

### 6.10 Headers & transport (R-32/R-33)

- Every response: `Strict-Transport-Security: max-age=63072000; includeSubDomains`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'self'` (frontend-tuned), `Referrer-Policy: strict-origin-when-cross-origin`. Via helmet + explicit HSTS.
- Boot check: `NODE_ENV=production` requires `COOKIE_SECURE=true` and a TLS story (`HTTPS_ENFORCED` / trusted proxy); violation → hard crash (R-33, R-36).
- pino-http serializers strip query strings from access logs (emailed token links never leak into logs — see §11 #7).

**Trust-proxy topology:** when the app runs behind a reverse proxy or load balancer (nginx, Caddy, ALB, Traefik, …), set `TRUST_PROXY` (config, integer hop count, default `0`) so Express honors the forwarded headers — the access log then records the real client IP rather than the proxy's, and any future client-IP-derived behavior (per-IP rate limits, `security_events.ip_address`) resolves correctly. The proxy must sanitize `X-Forwarded-For`: only trusted proxies may populate it, and the app never trusts a client-supplied value. Raw (non-proxied) deployments keep the default `0` and need no change.

### 6.11 Config (R-35/R-36)

`.env` → zod schema → frozen typed config object. Every key below is externalized; required keys missing/ill-typed → `exit(1)` with a specific message. **Required everywhere:** `DATABASE_URL`, `FRONTEND_URL`, `AUTH_BASE_URL`, `MFA_ENCRYPTION_KEYS`. **Required additionally in production:** `COOKIE_SECURE=true`, `HTTPS_ENFORCED=true`, `EMAIL_PROVIDER=smtp`, `RATE_LIMITER_BACKEND=redis`, `SERVICE_API_KEY`, `JWT_PRIVATE_KEY`. Full list in `.env.example`.

| Key | Notes |
|---|---|
| `DATABASE_URL` | required |
| `DB_POOL_MIN` / `DB_POOL_MAX` | pool sizing (defaults 2 / 10); tuned at load, no code change |
| `FRONTEND_URL`, `AUTH_BASE_URL`, `ALLOWED_ORIGINS` | origin/CSRF + link building |
| `COOKIE_DOMAIN`, `COOKIE_SECURE`, `SESSION_EXPIRY_DAYS` | cookie spec (§5); secure forced in prod |
| `SESSION_SECRET` | accepted but **not used** (§11 #1); present only for forward-compat |
| `MFA_ENCRYPTION_KEYS` | ordered `v2:base64...,v1:base64...`; newest = encrypt key; prod requires ≥1 |
| `ARGON_MEMORY_KIB`, `ARGON_TIME_COST`, `ARGON_PARALLELISM`, `ARGON_HASH_LENGTH` | centralized hashing params (§7 of spec) |
| `RATE_LIMITER_BACKEND` (`memory`\|`redis`), `REDIS_URL`, per-endpoint thresholds | backend swap = config change; prod requires redis |
| `LOCK_DURATION_MIN`, `LOCK_ESCALATION_COUNT`, `CAPTCHA_CHALLENGER` (no-op in V1) | lockout + DoS-escalation seam (§6.6) |
| `SERVICE_API_KEY` | gates `POST /auth/introspect` (§8.1); required in prod |
| `JWT_PRIVATE_KEY` (RS256 PEM), `JWT_ISSUER`, `JWT_AUDIENCE`, `JWT_KID`, `JWT_ACCESS_TTL` | consumer access tokens (§5.1); key required in prod; `JWT_ACCESS_TTL` default 15 min |
| `EMAIL_PROVIDER` (`console`\|`smtp`), `EMAIL_FROM`, `SMTP_URL`, `EMAIL_RETRY_MAX`, `EMAIL_RETRY_BACKOFF_MS` | outbox worker (§6.12) |
| `RETENTION_DAYS` | retention job window (default 90, §6.12) |
| `NODE_ENV`, `PORT`, `LOG_LEVEL`, `TRUST_PROXY`, `HTTPS_ENFORCED` | runtime |

### 6.12 Email delivery — DB outbox (R-20 sidecar)

Email is **never sent inline on the request path.** Signup/forgot/resend write an `email_outbox` row in the **same DB transaction** as the token creation (token + email are atomic; no inconsistent states). A small in-process worker (setImmediate-style poller, V1 — swappable to a real queue without touching the core) picks due rows and dispatches via `EmailProvider` with retry + exponential backoff (`EMAIL_RETRY_MAX` / `EMAIL_RETRY_BACKOFF_MS`). Delivery failures degrade the worker only — signup/reset endpoints stay fast and consistent. Idempotent by design: a row is either `sent_at` or retried; re-running the poller is safe.

### 6.13 Data retention job (R-29, mechanism not just policy)

`RETENTION_DAYS` (default 90) is config; a scheduled job (node-cron in-process, V1; `pg_cron` is the DB-side alternative) runs hourly and sets `ip_address = NULL`, `user_agent = NULL` on `sessions` and `security_events` rows older than the window. Idempotent and safe to re-run. Runs from Phase 5 onward; covered by an integration test.

---

## 7. Token model (R-13/R-14)

| Kind | TTL | Used by |
|---|---|---|
| EMAIL_VERIFICATION | 24 h | signup verify, resend |
| PASSWORD_RESET | 30 min | forgot → reset |
| MFA_PENDING | 5 min | login-with-MFA challenge |

All tokens: `randomBytes(32)` base64url (CSPRNG), stored **only as sha256** in `tokens`, single-use (marked `used_at` / row consumed on redemption), expiring per above. Raw tokens are never logged; traceability uses the token id/hash (R-14). Reset completion invalidates the token **and** all sessions (R-15).

**MFA_PENDING nuance:** consumed on *success* only. Failed TOTP attempts increment `failed_attempts` in `metadata`; at the §6.6 threshold (5) the token is invalidated → a brute-force can never loop against one challenge. This is still single-use by design — redemption is success, and the row is deleted on redemption or threshold.
---

## 8. API map (v1)

Base path `/api/v1`. All requests/responses JSON. Auth legend: **public** = no auth; **session** = valid session cookie; **challenge** = valid `mfaPendingToken`.

| # | Method & path | Auth | Purpose | Rate limit |
|---|---|---|---|---|
| 1 | POST /auth/signup | public | register (generic response; user starts PENDING_VERIFICATION) | 5/h/IP |
| 2 | POST /auth/login | public | password login; returns `mfaRequired` + `mfaPendingToken` when enrolled | 5 fails/15min (email,IP) + 20/min/IP |
| 3 | POST /auth/logout | session | revoke current session server-side + clear cookie | 30/min/IP |
| 4 | GET /auth/me | session | profile: id, email, names, verified, status, mfaEnabled, lastLoginAt | 60/min/IP |
| 5 | GET /auth/sessions | session | list own sessions (id, created/expires/lastUsed, ip, ua, current) | 30/min/IP |
| 6 | DELETE /auth/sessions/:id | session | revoke one (scoped to owner; foreign id → 404) | 30/min/IP |
| 7 | DELETE /auth/sessions/all | session | revoke all, current session included (re-login required) | 10/min/IP |
| 8 | POST /auth/verify-email | public | `{ token }` → ACTIVE + `EMAIL_VERIFIED` | 10/h/IP |
| 9 | POST /auth/resend-verification | public | `{ email }` → generic response | 3/h/email |
| 10 | POST /auth/forgot-password | public | `{ email }` → generic response | 5/h/(email,IP) |
| 11 | POST /auth/reset-password | public | `{ token, newPassword }` → invalidates all sessions | 5/h/(email,IP) |
| 12 | POST /auth/change-password | session | `{ currentPassword, newPassword }` → revokes all sessions except current | 5/15min/IP |
| 13 | POST /auth/mfa/enroll | session | start TOTP enrollment → otpauth URI, QR, recovery codes | 3/h/IP |
| 14 | POST /auth/mfa/verify | challenge or session | `{ mfaPendingToken?, code? / recoveryCode? }` → session (challenge) or enable (enroll) | 5 fails/15min per user (pending-token keyed) |
| 15 | POST /auth/mfa/disable | session | `{ code }` → removes credential + recovery codes | 3/h/IP |
| 16 | POST /auth/introspect | service key | `{ sessionSecret }` → `{ valid, userId, email, emailVerified, expiresAt }`; for service-to-service validation (§8.1) | 600/min/key |
| 17 | POST /auth/tokens | session | mint short-lived (default 15 min) RS256 access token: `sub`, `email`, `email_verified`, `status`, `iss`/`aud`/`jti` — no secrets in claims (§5.1, §8.2) | 10/min/IP |

Notes:

- **R-10:** endpoints 1–2, 9–11 issue no cookies. Only 2 (no-MFA path), 11-adjacent re-login, and 14 issue the session cookie.
- **IDOR:** endpoint 6 is owner-scoped; `404` for foreign/unknown ids.
- **R-11:** no response ever contains passwordHash, mfaSecret, session secret (except as *input* to #16), or internal metadata.
- Errors: `VALIDATION(400)`, `INVALID_CREDENTIALS(401)`, `MFA_REQUIRED(200 + mfaRequired)`, `TOKEN_INVALID(400)`, `RATE_LIMITED(429 + Retry-After)`, `UNAUTHENTICATED(401)`, `NOT_FOUND(404)`, `INVALID_ORIGIN(403)`, `CONFLICT(409)`, `INTERNAL(500)`.

### 8.1 Service-to-service session validation (the reusability seam)

`POST /api/v1/auth/introspect` — body `{ sessionSecret }`, header `X-Service-Key: <SERVICE_API_KEY>`:

- Constant-time key comparison; wrong/missing key → `401 UNAUTHENTICATED`; rate-limited per key (600/min).
- Returns `{ valid: false }` for unknown/expired/revoked sessions — no existence oracle beyond that.
- The secret is a credential: never logged (pino redaction covers it), never persisted beyond the request, never echoed.
- Exempt from Origin enforcement (service clients don't send Origin); intended for edge-gated consumers (internal network / mTLS), not the public frontend origin.
- `packages/session` (phase 7) ships `requireSession({ apiBaseUrl, serviceApiKey, cookieName })`: reads the platform cookie from the forwarded request, calls introspect, attaches `req.auth = { userId, email, emailVerified, expiresAt }`; absent/invalid → `401`. **Transport caveat (documented):** the forwarded cookie is only visible to a consumer backend sharing the cookie's origin scope (same host or behind the same edge/proxy). Cross-domain consumers get an out-of-band delegation flow — future work, not V1.

### 8.2 Consumer access-token validation (JWT path)

For consumers that cannot receive the platform cookie (cross-origin APIs, queue workers, mobile backends), `packages/session` also ships `verifyJwt({ publicKey, issuer, audience, clockTolerance })`:

- Verify `alg: RS256`, signature against the platform public key (distributed out-of-band), `iss === JWT_ISSUER`, `aud === JWT_AUDIENCE`, `exp` within clock tolerance; reject missing/`typ`-mismatched tokens.
- On success attaches `req.auth = { userId, email, emailVerified, status }` from claims — **no per-request round-trip**, matching the consumer's stateless-API constraint (§5.1).
- **Trust boundary:** claims are the minted snapshot at session time; identity state changes (suspension, MFA disable) propagate within ≤15 min. Consumers that need hard revocation use the introspect path (§8.1) instead — both are first-class and documented.
- The platform public key is published at `GET /auth/.well-known/jwks.json` (public, cached by consumers; used by `verifyJwt` when configured with a URL instead of a static key).

### 8.3 Consumer-boundary decision record (2026-08-10)

The consumer boundary is HTTP-level reuse, recorded as a decision on 2026-08-10: consumers integrate with the platform over the API only — `POST /auth/introspect` (service-key gated, §8.1) plus `packages/session` middleware (`requireSession`, `verifyJwt`). The auth app is deliberately **not** extracted into an embeddable `packages/auth` library: no shared DB, no shared code, and consumers never import auth internals. The public API surface is the contract; nothing below it is.

---

## 9. Frontend plan (React + TypeScript + Vite)

- **Routing:** `/` (landing → /app), `/login`, `/signup`, `/verify-email?token=…`, `/forgot-password`, `/reset-password?token=…`, `/app` (dashboard: profile, sessions list w/ revoke, change password, MFA panel), `/app/mfa` (enroll wizard showing QR + one-time recovery codes).
- **Auth state:** `AuthContext` fetches `GET /auth/me` on boot; protected routes redirect to `/login`. Session lives entirely in the `HttpOnly` cookie — the frontend holds no tokens (R-19).
- **API client:** thin `fetch` wrapper, `credentials: 'include'`, uniform error handling (`ApiError` from the §6.9 shape), `X-Request-Id` surfaced in error toasts.
- **Dev:** Vite dev server proxies `/api` → Express. **Prod:** Express serves the built SPA with SPA fallback; same origin ⇒ SameSite=Strict CSRF posture holds.
- **Email links:** verification/reset links point to frontend routes; the frontend POSTs the token to the API (body, not URL) — see §11 #7.
- **No secrets in localStorage/sessionStorage anywhere** — including consumer access tokens minted via §5.1 (kept in memory only; enforced by a lint rule + review checklist).

---

## 10. Self-review vs threat checklist (§24)

| Threat | Mitigation | Status |
|---|---|---|
| Enumerate registered emails via login/signup/reset/verify | uniform response shapes; dummy-hash verify on unknown-user login; no email echo on signup; events-only distinction | covered (6.1) |
| Brute-force password or MFA code | per-(email,IP) + per-IP limiters (Redis-backed in prod — no per-instance weakening); persisted time-boxed account lock; MFA 5-fail per-user → challenge invalidated; `Retry-After` | covered (6.6) |
| Token reuse after redemption/expiry | single-use (used_at + delete-on-redeem), TTLs enforced on read, one external `TOKEN_INVALID` shape | covered (§7) |
| Session fixation (pre-auth upgraded in place) | no pre-auth session exists; fresh secret issued only post-auth; MFA stage issues nothing | covered (6.4) |
| Cookie read by JS / sent cross-site | HttpOnly + Secure + SameSite=Strict + `__Host-` prefix + **fail-closed** Origin/Referer/Host checks (state-changing requests without a valid origin are rejected, never passed) | covered (6.3, §5) |
| Any secret written to a log | pino serializers redact query strings; event metadata whitelist; R-27 items enumerated in a shared redaction list | covered (6.8, 6.10) |
| Logout leaves server session valid | logout marks `revoked_at` in DB, then clears cookie; revoke-all endpoint for paranoid cleanup | covered (§5, §8 #3) |
| User IDs guessable / IDOR on /sessions/:id | ULID ids; owner-scoped WHERE + 404 for foreign ids; ids never sequential | covered (§4, §8 #6) |
| Password reset leaves sessions alive | reset invalidates token + all sessions (R-15); change-password revokes all but current | covered (6.5→§7, §8 #12) |
| App runs with missing security config | zod config; missing required secrets → exit(1) at boot | covered (6.11) |
| Security headers missing | helmet + HSTS on every response; boot-enforced in prod | covered (6.10) |
| Minted access token stolen / persisted by frontend | token held in memory only (never localStorage, §9); 15-min TTL; `iss`+`aud` pinned; RS256 — swapping `JWT_PRIVATE_KEY` kills all outstanding tokens in ≤15 min | covered (5.1) |

**Fixes found during self-review (now baked into the design):**

1. Access-log query-string leakage — pino-http must strip query strings (emailed tokens).
2. `/sessions/:id` foreign-owner must be 404, not 403/200 (existence oracle).
3. Session lookup must be a single query on `token_hash` (no email-first two-step timing).
4. `USER_DISABLED` error code is internal-only; client always sees `INVALID_CREDENTIALS`.
5. Verify-email endpoint must not reveal *why* a token failed (one `TOKEN_INVALID` code).
6. MFA-failure counter must be per user (resolved from the pending token, not IP) and persist across process restarts → count lives in token `metadata`, DB-backed account lock.
7. Origin/Referer both absent on a state-changing request → fail **closed** (`403`), never pass open.
8. `POST /auth/introspect` added — service-to-service session validation over the API (§8.1); without it, `packages/session` would have to touch the DB, violating the API boundary.
9. Email moved to a DB outbox (§6.12): same-transaction write + retrying worker; SMTP failure no longer breaks signup/reset and states stay consistent.
10. Rate-limiter backend is config-selected and **both** adapters (memory/Redis) ship in Phase 1; prod enforces redis — controls don't degrade silently under scaling.
11. MFA encryption key rotation via `key_version` + ordered `MFA_ENCRYPTION_KEYS` + lazy re-encrypt; rotation never locks out enrolled users.
12. `argon2.needsRehash` on successful login — param upgrades reach the whole user base over time.
13. Retention is a scheduled job (`RETENTION_DAYS`), not a SQL comment.
14. Lockout-DoS accepted as a documented risk with a `CaptchaChallenger`/progressive-delay escalation seam (disabled by default).
15. MFA-verify throttling keyed per user on the pending-token row; spreading guesses across tokens cannot bypass.
16. JWT bridge added — consumers with a no-cookie, Bearer-token architecture get verifiable claims (`sub`/`email`/`email_verified`, `iss`/`aud`, 15-min TTL) without sharing our DB or session store; cookies remain the revocable credential (§5.1, §8.2).

---

## 11. Documented decisions & deviations

1. **`SESSION_SECRET` not required.** Session secrets are per-session CSPRNG values stored hashed; there is no server-wide signing secret to protect. Instead `MFA_ENCRYPTION_KEYS` (ordered, versioned key list) is required — it protects TOTP secrets at rest (R-23), supports rotation, and fails fast if missing.
2. **Breached-password check ships local** (Top-10k SHA-1 blocklist, k-anonymity prefix matching) behind an interface; HIBP range API is the swap-in.
3. **Account lock is time-boxed** (auto-clears after `LOCK_DURATION`); admin-clearing deferred (no admin tooling in V1).
4. **change-password** revokes all sessions except the current one (spec mandates full invalidation only for reset).
5. **Rate-limiter backend is config-selected** (`RATE_LIMITER_BACKEND=memory|redis`); both adapters ship from Phase 1 and prod requires redis (fail-fast). Fixed-window allows up to ~2x burst at window boundaries — accepted for V1; sliding-window/token-bucket is the documented upgrade path. The in-memory adapter is per-process: a per-key fixed-window `Map` with a stale-window sweep — entries whose window started more than `STALE_WINDOW_MS` (1 h) ago are evicted once the map crosses `MAX_ENTRIES_BEFORE_SWEEP` (10 000), at most once a minute — so it gives no cross-instance limits. Multi-instance deployments must use the Redis adapter (atomic `INCR` per window key with `PEXPIRE` on first hit; cross-instance by construction) or an external rate limiter. `GET /healthz` currently reports only the DB ping (`{ status, db: "up" | "down" }`); it must gain a Redis dimension before a multi-instance rollout.
6. **MFA-pending token travels in the response body** — it is a 5-min single-purpose capability (not a session), hashed at rest; acceptable and documented.
7. **Email-link tokens appear in URL query strings** (standard for email flows); mitigated: single-use + short TTL + hashed at rest + frontend POSTs to API + server access logs strip query strings (R-19 honored in letter and spirit).
8. **E2E tests run at the API level** (supertest flows §21); Playwright browser E2E is a documented follow-up, not a V1 gate.
9. **Lockout-DoS accepted risk:** a hard 15-min lock can be deliberately triggered by anyone who knows the victim's email. The `CaptchaChallenger`/progressive-delay escalation seam exists (config-gated, no-op in V1) but is disabled by default — a stated decision, not an oversight.
10. **`SameSite=Strict` trade-off:** the session cookie does not ride along on a fresh top-level navigation from an external link (e.g. deep-links from other consumer apps). Accepted: cross-app linking routes through the consumer's own session/redirect flow.
11. **Email outbox worker runs in-process** (poller with retry/backoff) in V1 — swappable to a real queue without touching the core (R-28-style seam, same shape as `SecurityEventExporter`).
12. **Consumer JWTs are stateless with a 15-min TTL** — no revocation list; key rotation is a config swap that kills all outstanding tokens within ≤15 min (documented kill-switch, §5.1). The session cookie stays the long-lived, revocable credential; the JWT is a snapshot projection of the session at mint time, and identity-state changes propagate to consumers within the TTL. This is the explicit trade-off chosen over per-request introspection when a consumer's architecture requires stateless Bearer auth (§8.2).

---

## 12. Testing & CI (§21, R-37)

- **Unit (vitest):** argon2id hash/verify params + `needsRehash` upgrade path, email normalization, ULID, token gen/expiry/single-use logic, AccountStatePolicy transitions, rate-limiter windows (memory **and** redis adapters), AES-GCM round-trip + key-version rotation (old key decrypts, new key re-encrypts, unknown version fails closed), password policy (min/max/blocklist), outbox retry/backoff scheduling.
- **Integration (supertest + `auuth_test` pg):** signup → verify → login → me → sessions → logout; forgot → reset → sessions invalidated; change-password; MFA enroll → verify → disable; recovery code redemption; introspect (valid/revoked/expired secret, bad key → 401, no secret in access logs); **JWT mint → verify** (`POST /auth/tokens` with cookie → jose verifies signature/`iss`/`aud`/claims; wrong audience / expired / tampered token rejected; JWKS endpoint serves the matching public key; claims contain no secrets).
- **Security tests:** brute-force simulation (5 fails → lock; 429s with Retry-After); enumeration timing sanity (unknown-email login cost >= known); expired/reused/foreign token rejection; session-fixation (no cookie pre-login; fresh secret per login); IDOR (revoke other user's session → 404); CSRF (bad Origin → 403, **both Origin+Referer absent → 403**); cookie-flag assertions (HttpOnly/Secure/SameSite/Path); injection payloads on every input field (zod rejects); retention job (older rows anonymized, idempotent re-run); lockout-escalation counters (N lockouts → escalation seam engaged when enabled).
- **E2E flows (§21):** (a) signup → verify → login → me → logout → me denied; (b) login → enroll MFA → logout → login → MFA challenge → session → disable.
- **CI (GitHub Actions):** Postgres service container; `npm run lint`, `typecheck`, `test`; `npm audit --audit-level=high`; **gitleaks** secret scan on every PR (R-37).

---

## 13. Phase plan (§23)

| Phase | Deliverable | Done when |
|---|---|---|
| 0 | this document + approval | user approves |
| 1 Foundation | scaffold, workspaces, config (fail-fast, full table §6.11 incl. `DB_POOL_MIN/MAX`), pino, pg/kysely + migrations (all §4 tables incl. `email_outbox`), AppError + error handler, request-id, test harness, docker-compose, **`RateLimiter` interface + memory AND redis adapters (backend via config)** | `GET /healthz` green; config crash tests pass; both limiter adapters pass the same suite |
| 2 Identity | users table, ULID ids, EmailNormalizer, AccountStatePolicy, argon2id hashing (centralized params, `needsRehash` seam), UserRepository/UserService | unit tests green |
| 3 Core auth | signup, login (dummy-hash + needsRehash), logout, /me, sessions (cookie spec, fixation-safe issuance, fail-closed origin check, rate limits from day one) | security tests: cookie flags, CSRF (incl. missing-origin), fixation, enumeration |
| 4 Verification & recovery | email verify, resend, forgot/reset/change password, token rules (§7), **email outbox + worker** wired to all token-issuing endpoints | token reuse/expiry/reset-invalidates-sessions tests green; outbox retry test green |
| 5 Security hardening | security-event log (full set, whitelist), brute-force/lock + escalation seam, **retention job (RETENTION_DAYS)**, **introspect + SERVICE_API_KEY**, enumeration pass over all endpoints | R-21/R-26–R-29 tests green; retention idempotency test green |
| 6 MFA | TOTP enroll/verify/disable, recovery codes, MFA_PENDING flow, AES-GCM at rest **with key_version rotation** | MFA e2e flows green; key-rotation unit tests green |
| 7 Integration | openapi.yaml (R-31), API docs, `packages/session` middleware + typed client (cookie introspect **and** `verifyJwt`), `POST /auth/tokens` + JWKS | a consumer-style test client authenticates via API only (no DB), on both the cookie and Bearer-JWT paths |
| 8 Test & review | full suite §21, npm audit + gitleaks, manual threat-checklist walk (§24) | definition of done (§25) all checked |

---

## 14. Definition of done (from spec §25)

- [ ] Signup, verify, login, /me, logout, session list/revoke work end-to-end
- [ ] Argon2id hashing with centralized, documented parameters
- [ ] Reset/verification tokens: CSPRNG, hashed at rest, single-use, expiring, never logged
- [ ] Sessions: fixation-safe issuance, hashed-at-rest secret, CSRF protection, secure cookie flags
- [ ] Rate limiting + brute-force lockout with concrete thresholds, pluggable backend
- [ ] Security-event log with the full event set, no secrets in any log
- [ ] MFA (TOTP) foundation with encrypted-at-rest secrets and recovery codes
- [ ] Security headers + HTTPS enforced, fail-fast config validation
- [ ] Structured error model, no leaked internals
- [ ] OpenAPI-documented, versioned API; layered architecture (no controller → DB shortcuts)
- [ ] Consumer access tokens (RS256 JWTs, 15-min TTL) mintable from a session; no secrets in claims; JWKS published
- [ ] Full test suite green; CI runs dependency + secret scanning
- [ ] Zero references to any consumer-project name anywhere in the codebase
