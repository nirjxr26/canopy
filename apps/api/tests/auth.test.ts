import { beforeAll, beforeEach, afterEach, describe, expect, it } from "vitest";
import request from "supertest";
import type { Express } from "express";
import { Kysely } from "kysely";
import { createApp } from "../src/app/app.js";
import { loadConfig } from "../src/infrastructure/config/config.js";
import { createLogger } from "../src/infrastructure/logging/logger.js";
import { createDb } from "../src/infrastructure/db/database.js";
import type { Database } from "../src/infrastructure/db/database.js";
import { createPasswordHasher } from "../src/infrastructure/crypto/password.js";
import { InMemoryRateLimiter } from "../src/infrastructure/ratelimit/memory-rate-limiter.js";
import { createUserRepository } from "../src/modules/identity/user-repository.js";
import { createUserService } from "../src/modules/identity/user-service.js";
import { createTokenRepository } from "../src/modules/identity/token-repository.js";
import { createTokenService } from "../src/modules/identity/token-service.js";
import { createMfaRepository } from "../src/modules/mfa/mfa-repository.js";
import { createMfaService } from "../src/modules/mfa/mfa-service.js";
import { createOutboxRepository } from "../src/modules/email/outbox-repository.js";
import { createEmailService, type EmailProvider, type EmailMessage } from "../src/modules/email/email-service.js";
import { createSessionRepository } from "../src/modules/session/session-repository.js";
import { createSessionService } from "../src/modules/session/session-service.js";
import { describeDb, resetTestDatabase, TEST_DATABASE_URL, TEST_MFA_KEY } from "./helpers/db.js";
import { migrateToLatest } from "../src/infrastructure/db/migrate.js";

const PASSWORD = "Correct-horse-battery-staple-1";
const BASE_URL = "/api/v1/auth";

class RecordingProvider implements EmailProvider {
  readonly kind = "console" as const;
  sent: EmailMessage[] = [];
  async send(message: EmailMessage): Promise<void> {
    this.sent.push(message);
  }
}

function makeTestConfig() {
  return loadConfig({
    NODE_ENV: "test",
    DATABASE_URL: TEST_DATABASE_URL,
    FRONTEND_URL: "http://localhost:5173",
    AUTH_BASE_URL: "http://localhost:3000",
    MFA_ENCRYPTION_KEYS: TEST_MFA_KEY,
    ARGON_MEMORY_KIB: "8192",
    ARGON_TIME_COST: "1",
    ARGON_PARALLELISM: "1",
  });
}

interface TestHarness {
  app: Express;
  db: Kysely<Database>;
  pool: { end(): Promise<void> };
  users: ReturnType<typeof createUserService>;
  provider: RecordingProvider;
}

function makeApp(): TestHarness {
  const config = makeTestConfig();
  const logger = createLogger("silent");
  const { db, pool } = createDb(config);
  const hasher = createPasswordHasher({
    memoryCostKiB: config.argonMemoryKib,
    timeCost: config.argonTimeCost,
    parallelism: config.argonParallelism,
    hashLength: config.argonHashLength,
  });
  const limiter = new InMemoryRateLimiter();
  const users = createUserService(createUserRepository(db), hasher);
  const sessions = createSessionService(createSessionRepository(db), { getById: users.getById }, config);
  const tokens = createTokenService(createTokenRepository(db));
  const mfa = createMfaService({
    repository: createMfaRepository(db),
    tokens,
    db,
    keys: config.mfaEncryptionKeys,
    issuer: config.jwtIssuer,
  });
  const provider = new RecordingProvider();
  const emails = createEmailService({
    outbox: createOutboxRepository(db),
    provider,
    config,
    keys: config.mfaEncryptionKeys,
    logger,
  });
  const app = createApp({ config, logger, db, hasher, limiter, users, sessions, tokens, emails, mfa, provider, keys: config.mfaEncryptionKeys });
  return { app, db, pool, users, provider };
}

function cookieOf(res: request.Response): string {
  const setCookie = res.headers["set-cookie"];
  const raw = Array.isArray(setCookie) ? setCookie[0] : undefined;
  if (typeof raw !== "string") {
    throw new Error("no Set-Cookie header");
  }
  return raw.split(";")[0]!;
}

async function signup(app: Express, email: string): Promise<request.Response> {
  return request(app)
    .post(`${BASE_URL}/signup`)
    .set("Origin", "http://localhost:5173")
    .send({ email, password: PASSWORD });
}

async function login(app: Express, email: string, password: string = PASSWORD): Promise<request.Response> {
  return request(app)
    .post(`${BASE_URL}/login`)
    .set("Origin", "http://localhost:5173")
    .send({ email, password });
}

describeDb("auth endpoints", () => {
  beforeAll(async () => {
    await resetTestDatabase();
    await migrateToLatest({ databaseUrl: TEST_DATABASE_URL, dbPoolMin: 2, dbPoolMax: 10 });
  });

  let harness: TestHarness;
  beforeEach(() => {
    harness = makeApp();
  });
  afterEach(async () => {
    await harness.pool.end();
  });

  describe("signup", () => {
    it("creates an account and returns the generic shape", async () => {
      const res = await signup(harness.app, "signup-1@example.com");
      expect(res.status).toBe(201);
      expect(res.body.user.id).toMatch(/^usr_/);
      expect(res.body.user.email).toBe("signup-1@example.com");
      expect(JSON.stringify(res.body)).not.toContain("password");
    });

    it("is generic for duplicate accounts (no enumeration)", async () => {
      const first = await signup(harness.app, "signup-2@example.com");
      const second = await signup(harness.app, "signup-2@example.com");
      expect(first.status).toBe(201);
      expect(second.status).toBe(201);
      expect(second.body.user.id).toBe(first.body.user.id);
    });

    it("rejects a weak password", async () => {
      const res = await request(harness.app)
        .post(`${BASE_URL}/signup`)
        .set("Origin", "http://localhost:5173")
        .send({ email: "signup-3@example.com", password: "short" });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe("VALIDATION");
    });

    it("rejects an invalid email", async () => {
      const res = await request(harness.app)
        .post(`${BASE_URL}/signup`)
        .set("Origin", "http://localhost:5173")
        .send({ email: "not-an-email", password: PASSWORD });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe("VALIDATION");
    });
  });

  describe("login", () => {
    async function activeUser(email: string) {
      await signup(harness.app, email);
      const user = await harness.users.findByEmail(email);
      await harness.users.verifyEmail(user!.id);
      return user!;
    }

    it("rejects unknown email with generic 401", async () => {
      const res = await login(harness.app, "ghost@example.com");
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe("INVALID_CREDENTIALS");
    });

    it("rejects a wrong password", async () => {
      await activeUser("login-1@example.com");
      const res = await login(harness.app, "login-1@example.com", "wrong-password-1234");
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe("INVALID_CREDENTIALS");
    });

    it("rejects an unverified account", async () => {
      await signup(harness.app, "login-2@example.com");
      const res = await login(harness.app, "login-2@example.com");
      expect(res.status).toBe(401);
    });

    it("succeeds and sets a hardened session cookie", async () => {
      await activeUser("login-3@example.com");
      const res = await login(harness.app, "login-3@example.com");
      expect(res.status).toBe(200);
      expect(res.body.user.email).toBe("login-3@example.com");
      const setCookie = res.headers["set-cookie"][0];
      expect(setCookie).toContain("ap_session=");
      expect(setCookie).toContain("HttpOnly");
      expect(setCookie).toContain("SameSite=Strict");
      expect(setCookie).toContain("Path=/");
      expect(setCookie).not.toContain("Domain=");
    });

    it("persists the cookie for sessionExpiryDays by default", async () => {
      await activeUser("login-3b@example.com");
      const res = await login(harness.app, "login-3b@example.com");
      const setCookie = res.headers["set-cookie"][0];
      expect(setCookie).toMatch(/Max-Age=\d+/);
    });

    it("omits Max-Age when persistent is false (browser-session cookie)", async () => {
      await activeUser("login-3c@example.com");
      const res = await request(harness.app)
        .post(`${BASE_URL}/login`)
        .set("Origin", "http://localhost:5173")
        .send({ email: "login-3c@example.com", password: PASSWORD, persistent: false });
      expect(res.status).toBe(200);
      const setCookie = res.headers["set-cookie"][0];
      expect(setCookie).not.toContain("Max-Age");
    });

    it("issues a fresh session secret on every login (fixation-safe)", async () => {
      await activeUser("login-4@example.com");
      const first = await login(harness.app, "login-4@example.com");
      const second = await login(harness.app, "login-4@example.com");
      expect(cookieOf(first)).not.toBe(cookieOf(second));
    });
  });

  describe("me", () => {
    async function sessionOf(email: string): Promise<string> {
      await signup(harness.app, email);
      const user = await harness.users.findByEmail(email);
      await harness.users.verifyEmail(user!.id);
      const res = await login(harness.app, email);
      return cookieOf(res);
    }

    async function sessionRow(email: string) {
      return harness.db
        .selectFrom("sessions")
        .innerJoin("users", "users.id", "sessions.user_id")
        .select("sessions.id")
        .where("users.email", "=", email)
        .executeTakeFirstOrThrow();
    }

    it("returns 401 without a session cookie", async () => {
      const res = await request(harness.app).get(`${BASE_URL}/me`);
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe("UNAUTHENTICATED");
    });

    it("returns the user shape", async () => {
      const cookie = await sessionOf("me-1@example.com");
      const res = await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookie);
      expect(res.status).toBe(200);
      expect(res.body.user).toMatchObject({
        id: expect.stringMatching(/^usr_/),
        email: "me-1@example.com",
        emailVerified: true,
        status: "ACTIVE",
        mfaEnabled: false,
      });
    });

    it("rejects a revoked session", async () => {
      const cookie = await sessionOf("me-2@example.com");
      const row = await sessionRow("me-2@example.com");
      await harness.db
        .updateTable("sessions")
        .set({ revoked_at: new Date() })
        .where("id", "=", row.id)
        .execute();
      const res = await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookie);
      expect(res.status).toBe(401);
    });

    it("rejects an expired session", async () => {
      const cookie = await sessionOf("me-3@example.com");
      const row = await sessionRow("me-3@example.com");
      await harness.db
        .updateTable("sessions")
        .set({ expires_at: new Date(Date.now() - 60_000) })
        .where("id", "=", row.id)
        .execute();
      const res = await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookie);
      expect(res.status).toBe(401);
    });

    it("touches last_used_at (throttled)", async () => {
      const cookie = await sessionOf("me-4@example.com");
      const row = await sessionRow("me-4@example.com");
      const stale = new Date(Date.now() - 120_000);
      await harness.db
        .updateTable("sessions")
        .set({ last_used_at: stale })
        .where("id", "=", row.id)
        .execute();
      await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookie);
      const after = await harness.db
        .selectFrom("sessions")
        .select("last_used_at")
        .where("id", "=", row.id)
        .executeTakeFirstOrThrow();
      expect(after.last_used_at.getTime()).toBeGreaterThan(stale.getTime());
    });
  });

  describe("sessions", () => {
    async function twoSessions(email: string): Promise<[string, string]> {
      await signup(harness.app, email);
      const user = await harness.users.findByEmail(email);
      await harness.users.verifyEmail(user!.id);
      const first = await login(harness.app, email);
      const second = await login(harness.app, email);
      return [cookieOf(first), cookieOf(second)];
    }

    it("lists sessions and marks the current one", async () => {
      const [cookieA, cookieB] = await twoSessions("sessions-1@example.com");
      const res = await request(harness.app).get(`${BASE_URL}/sessions`).set("Cookie", cookieB);
      expect(res.status).toBe(200);
      expect(res.body.sessions).toHaveLength(2);
      const current = res.body.sessions.filter((s: { isCurrent: boolean }) => s.isCurrent);
      expect(current).toHaveLength(1);
      expect(JSON.stringify(res.body)).not.toContain("token_hash");
    });

    it("revokes a session owner-scoped; foreign id is 404", async () => {
      const [cookieA, cookieB] = await twoSessions("sessions-2@example.com");
      const list = await request(harness.app).get(`${BASE_URL}/sessions`).set("Cookie", cookieA);
      const other = list.body.sessions.find((s: { isCurrent: boolean }) => !s.isCurrent);
      const res = await request(harness.app).delete(`${BASE_URL}/sessions/${other.id}`).set("Origin", "http://localhost:5173").set("Cookie", cookieA);
      expect(res.status).toBe(204);
      const foreign = await request(harness.app).delete(`${BASE_URL}/sessions/usr_does-not-exist`).set("Origin", "http://localhost:5173").set("Cookie", cookieA);
      expect(foreign.status).toBe(404);
      expect(foreign.body.error.code).toBe("NOT_FOUND");
    });

    it("revoked session stops working immediately", async () => {
      const [cookieA, cookieB] = await twoSessions("sessions-3@example.com");
      const list = await request(harness.app).get(`${BASE_URL}/sessions`).set("Cookie", cookieA);
      const other = list.body.sessions.find((s: { isCurrent: boolean }) => !s.isCurrent);
      await request(harness.app).delete(`${BASE_URL}/sessions/${other.id}`).set("Origin", "http://localhost:5173").set("Cookie", cookieA);
      const dead = await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookieB);
      expect(dead.status).toBe(401);
    });

    it("revokes all sessions", async () => {
      const [cookieA, cookieB] = await twoSessions("sessions-4@example.com");
      const res = await request(harness.app).post(`${BASE_URL}/sessions/revoke-all`).set("Origin", "http://localhost:5173").set("Cookie", cookieA);
      expect(res.status).toBe(204);
      const a = await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookieA);
      const b = await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookieB);
      expect(a.status).toBe(401);
      expect(b.status).toBe(401);
    });
  });

  describe("logout", () => {
    it("revokes the session and clears the cookie", async () => {
      await signup(harness.app, "logout-1@example.com");
      const user = await harness.users.findByEmail("logout-1@example.com");
      await harness.users.verifyEmail(user!.id);
      const loginRes = await login(harness.app, "logout-1@example.com");
      const res = await request(harness.app).post(`${BASE_URL}/logout`).set("Origin", "http://localhost:5173").set("Cookie", cookieOf(loginRes));
      expect(res.status).toBe(204);
      expect(Array.isArray(res.headers["set-cookie"]) ? res.headers["set-cookie"].join(";") : res.headers["set-cookie"]).toContain("Expires=Thu, 01 Jan 1970");
      const me = await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookieOf(loginRes));
      expect(me.status).toBe(401);
    });
  });

  describe("rate limits", () => {
    it("limits signups per window (429 + Retry-After)", async () => {
      const results: number[] = [];
      for (let i = 0; i < 6; i++) {
        const res = await signup(harness.app, `ratelimit-signup-${i}@example.com`);
        results.push(res.status);
      }
      expect(results.slice(0, 5)).toEqual([201, 201, 201, 201, 201]);
      expect(results[5]).toBe(429);
      const last = await request(harness.app)
        .post(`${BASE_URL}/signup`)
        .set("Origin", "http://localhost:5173")
        .send({ email: "ratelimit-signup-x@example.com", password: PASSWORD });
      expect(last.body.error.code).toBe("RATE_LIMITED");
      expect(Number(last.headers["retry-after"])).toBeGreaterThan(0);
    });

    it("locks out after repeated failed logins", async () => {
      for (let i = 0; i < 5; i++) {
        const res = await login(harness.app, "ratelimit-login@example.com", "wrong-password-1234");
        expect(res.status).toBe(401);
      }
      const sixth = await login(harness.app, "ratelimit-login@example.com", "wrong-password-1234");
      expect(sixth.status).toBe(429);
      expect(sixth.body.error.code).toBe("RATE_LIMITED");
    });
  });

  describe("origin check", () => {
    it("rejects cross-origin state-changing requests", async () => {
      const res = await request(harness.app)
        .post(`${BASE_URL}/signup`)
        .set("Origin", "http://evil.example")
        .send({ email: "origin-1@example.com", password: PASSWORD });
      expect(res.status).toBe(403);
      expect(res.body.error.code).toBe("INVALID_ORIGIN");
    });

    it("allows configured origins", async () => {
      const res = await signup(harness.app, "origin-2@example.com");
      expect(res.status).toBe(201);
    });

    it("does not gate safe methods", async () => {
      const res = await request(harness.app).get(`${BASE_URL}/me`).set("Origin", "http://evil.example");
      expect(res.status).toBe(401);
    });
  });
});
