# MFA Feature — Final Report

Status: **COMPLETE** — all tests green, live smoke test passes end-to-end.

## Delivered

Optional, user-configured TOTP MFA with recovery codes, wired through login, on top of the existing Express + PostgreSQL + TypeScript auth monorepo (`apps/api` + `apps/web`).

### New modules (apps/api)
| File | Purpose |
|---|---|
| `src/modules/mfa/mfa-repository.ts` | SQL: insert/fetch secret, consume recovery codes |
| `src/modules/mfa/mfa-service.ts` | enroll / confirm / verify / disable / recovery-code single-use |
| `src/app/routes/mfa.ts` | HTTP: `POST /api/v1/auth/{enroll,confirm,verify,disable}` |
| `src/infrastructure/crypto/totp.ts` | RFC 6238 TOTP generate/verify, base32 secret, otpauth URL, recovery codes (`generateTotpCode` added for tests) |
| `src/infrastructure/crypto/cipher.ts` | AES-256-GCM encrypt/decrypt with key-version rotation |
| `src/infrastructure/config/config.ts` | `MFA_ENCRYPTION_KEYS` (`v<ver>:<base64 32-byte key>`) parsing |
| `src/modules/email/outbox.ts` + `email-provider.ts` | Email queue drain worker + provider interface |
| `apps/web/src/lib/mfa.ts` | Web TOTP verification helper |

### Flow
Signup → verify email → login (session) → `POST /enroll` (secret + otpauthUrl) → `POST /confirm` (TOTP code → 10 single-use recovery codes) → subsequent logins return `{ mfaRequired: true, mfaToken }` (no cookie) → `POST /verify` (TOTP or recovery code → session cookie). 5 failed attempts burn the `MFA_PENDING` token. `POST /disable` (with code) removes MFA.

## Verification

| Check | Result |
|---|---|
| Unit/integration suite (`vitest run`) | **170/170 passed** (17 files; redis-dependent tests skip gracefully) |
| API typecheck (`tsc --noEmit`) | Clean |
| Web typecheck + `vite build` | Clean, builds |
| Live smoke test (HTTP against running server, `tests/smoke-test.mjs`) | **45/45 assertions passed, exit 0** |

Smoke test covers: healthz, signup ×2, activation, login, `/me`, sessions, enroll, confirm (bad → 400 `MFA_INVALID`; good → 10 recovery codes), `mfaEnabled` in `/me`, MFA-required login (token, no cookie), verify wrong code → `MFA_INVALID`, verify correct TOTP → 200 + session cookie, recovery-code login, recovery single-use, disable (bad/good), login after disable, logout (204), unknown route 404, malformed JSON 400.

## Bugs found & fixed along the way

1. **Test DB reset race** (`tests/helpers/db.ts`) — `DROP SCHEMA public CASCADE` while the connection's `search_path` included `public` failed silently. Fixed by `SET search_path TO pg_catalog, pg_temp` before the drop.
2. **Double-hashed MFA token** (`src/app/routes/mfa.ts:61`) — route pre-hashed the token, then `tokens.findByHash()` hashed again → token never found (all `/verify` calls returned `TOKEN_INVALID`). Removed the redundant outer `hashToken`.
3. **Test expectation bug** (`tests/mfa.test.ts`) — `TOKEN_INVALID` maps to HTTP 400, test expected 401; corrected.
4. **Smoke-test shape bugs** — `/me` returns `{ user: ... }`; logout returns 204; corrected assertions, and removed a redundant enroll call that tripped the shared `mfaEnroll` (3/hour) rate-limit bucket.

## Config notes
- `MFA_ENCRYPTION_KEYS` requires `v1:<base64(32 bytes)>` — AES-256-GCM needs exactly 32-byte keys (dev/test keys fixed accordingly).
- Dev-only smoke accommodation in `apps/api/.env`: `RATE_LIMITS_JSON={"mfaVerify":{"limit":20,"windowMs":60000}}` — the in-memory limiter keys only by IP, so concurrent 60s-window endpoints share a bucket and the default 10-min req count tripped during the scripted flow. Production defaults (redis backend) are untouched.

## Artifacts
- `apps/api/tests/mfa.test.ts` — 13 endpoint tests (replaces/extracts from the Notion plan's manual verification).
- `apps/api/tests/smoke-test.mjs` — repeatable live HTTP smoke test (uses dev DB `auuth`; needs `postgres` + API on :3000).

## Left running
API server on port 3000 (listener was PID 10540 at last check; `GET /healthz` → `{"status":"ok","db":"up"}`).