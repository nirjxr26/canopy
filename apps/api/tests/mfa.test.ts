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
import { generateTotpCode } from "../src/infrastructure/crypto/totp.js";
import { describeDb, resetTestDatabase, TEST_DATABASE_URL, TEST_MFA_KEY } from "./helpers/db.js";
import { migrateToLatest } from "../src/infrastructure/db/migrate.js";

const PASSWORD = "correct-horse-battery-staple-1";
const MFA_BASE = "/api/v1/auth";
const AUTH_BASE = "/api/v1/auth";

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
    keys: config.mfaEncryptionKeys,
    issuer: config.jwtIssuer,
  });
  const provider = new RecordingProvider();
  const emails = createEmailService({
    outbox: createOutboxRepository(db),
    provider,
    config,
  });
  const app = createApp({ config, logger, db, hasher, limiter, users, sessions, tokens, emails, mfa });
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
    .post(`${AUTH_BASE}/signup`)
    .set("Origin", "http://localhost:5173")
    .send({ email, password: PASSWORD });
}

async function activeUser(app: Express, harness: TestHarness, email: string) {
  await signup(app, email);
  const user = await harness.users.findByEmail(email);
  await harness.users.verifyEmail(user!.id);
  return user!;
}

async function login(app: Express, email: string, password: string = PASSWORD): Promise<request.Response> {
  return request(app)
    .post(`${AUTH_BASE}/login`)
    .set("Origin", "http://localhost:5173")
    .send({ email, password });
}

describeDb("mfa endpoints", () => {
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

  describe("enroll", () => {
    it("requires a session", async () => {
      const res = await request(harness.app).post(`${MFA_BASE}/enroll`);
      expect(res.status).toBe(401);
    });

    it("returns secret and otpauthUrl", async () => {
      await activeUser(harness.app, harness, "mfa-enroll-1@example.com");
      const loginRes = await login(harness.app, "mfa-enroll-1@example.com");
      const cookie = cookieOf(loginRes);
      const res = await request(harness.app)
        .post(`${MFA_BASE}/enroll`)
        .set("Cookie", cookie);
      expect(res.status).toBe(200);
      expect(res.body.secret).toMatch(/^[A-Z2-7]{16,}$/);
      expect(res.body.otpauthUrl).toMatch(/^otpauth:\/\/totp\//);
    });
  });

  describe("confirm", () => {
    it("rejects wrong code", async () => {
      await activeUser(harness.app, harness, "mfa-confirm-1@example.com");
      const loginRes = await login(harness.app, "mfa-confirm-1@example.com");
      const cookie = cookieOf(loginRes);
      const enrollRes = await request(harness.app)
        .post(`${MFA_BASE}/enroll`)
        .set("Cookie", cookie);
      const { secret } = enrollRes.body;
      const res = await request(harness.app)
        .post(`${MFA_BASE}/confirm`)
        .set("Cookie", cookie)
        .send({ secret, code: "000000" });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe("MFA_INVALID");
    });

    it("confirms with correct code and returns recovery codes", async () => {
      await activeUser(harness.app, harness, "mfa-confirm-2@example.com");
      const loginRes = await login(harness.app, "mfa-confirm-2@example.com");
      const cookie = cookieOf(loginRes);
      const enrollRes = await request(harness.app)
        .post(`${MFA_BASE}/enroll`)
        .set("Cookie", cookie);
      const { secret } = enrollRes.body;
      const code = generateTotpCode(secret);
      const res = await request(harness.app)
        .post(`${MFA_BASE}/confirm`)
        .set("Cookie", cookie)
        .send({ secret, code });
      expect(res.status).toBe(200);
      expect(Array.isArray(res.body.recoveryCodes)).toBe(true);
      expect(res.body.recoveryCodes.length).toBe(10);
    });

    it("rejects double confirm", async () => {
      await activeUser(harness.app, harness, "mfa-confirm-3@example.com");
      const loginRes = await login(harness.app, "mfa-confirm-3@example.com");
      const cookie = cookieOf(loginRes);
      const enrollRes = await request(harness.app)
        .post(`${MFA_BASE}/enroll`)
        .set("Cookie", cookie);
      const { secret } = enrollRes.body;
      const code = generateTotpCode(secret);
      await request(harness.app)
        .post(`${MFA_BASE}/confirm`)
        .set("Cookie", cookie)
        .send({ secret, code });
      const res = await request(harness.app)
        .post(`${MFA_BASE}/confirm`)
        .set("Cookie", cookie)
        .send({ secret, code });
      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe("CONFLICT");
    });
  });

  describe("me shows mfaEnabled", () => {
    it("shows mfaEnabled true after confirm", async () => {
      await activeUser(harness.app, harness, "mfa-me-1@example.com");
      const loginRes = await login(harness.app, "mfa-me-1@example.com");
      const cookie = cookieOf(loginRes);
      const enrollRes = await request(harness.app)
        .post(`${MFA_BASE}/enroll`)
        .set("Cookie", cookie);
      const { secret } = enrollRes.body;
      const code = generateTotpCode(secret);
      await request(harness.app)
        .post(`${MFA_BASE}/confirm`)
        .set("Cookie", cookie)
        .send({ secret, code });
      const meRes = await request(harness.app)
        .get(`${AUTH_BASE}/me`)
        .set("Cookie", cookie);
      expect(meRes.status).toBe(200);
      expect(meRes.body.user.mfaEnabled).toBe(true);
    });
  });

  describe("login with MFA required", () => {
    it("returns mfaRequired and mfaToken instead of session", async () => {
      await activeUser(harness.app, harness, "mfa-login-1@example.com");
      const loginRes1 = await login(harness.app, "mfa-login-1@example.com");
      const cookie = cookieOf(loginRes1);
      const enrollRes = await request(harness.app)
        .post(`${MFA_BASE}/enroll`)
        .set("Cookie", cookie);
      const { secret } = enrollRes.body;
      const code = generateTotpCode(secret);
      await request(harness.app)
        .post(`${MFA_BASE}/confirm`)
        .set("Cookie", cookie)
        .send({ secret, code });
      const loginRes2 = await login(harness.app, "mfa-login-1@example.com");
      expect(loginRes2.status).toBe(200);
      expect(loginRes2.body.mfaRequired).toBe(true);
      expect(typeof loginRes2.body.mfaToken).toBe("string");
    });
  });

  describe("verify", () => {
    it("rejects wrong code", async () => {
      await activeUser(harness.app, harness, "mfa-verify-1@example.com");
      const loginRes1 = await login(harness.app, "mfa-verify-1@example.com");
      const cookie = cookieOf(loginRes1);
      const enrollRes = await request(harness.app)
        .post(`${MFA_BASE}/enroll`)
        .set("Cookie", cookie);
      const { secret } = enrollRes.body;
      const code = generateTotpCode(secret);
      await request(harness.app)
        .post(`${MFA_BASE}/confirm`)
        .set("Cookie", cookie)
        .send({ secret, code });
      const loginRes2 = await login(harness.app, "mfa-verify-1@example.com");
      const { mfaToken } = loginRes2.body;
      const res = await request(harness.app)
        .post(`${MFA_BASE}/verify`)
        .send({ mfaToken, code: "000000" });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe("MFA_INVALID");
    });

    it("returns user and session on valid code", async () => {
      await activeUser(harness.app, harness, "mfa-verify-2@example.com");
      const loginRes1 = await login(harness.app, "mfa-verify-2@example.com");
      const cookie = cookieOf(loginRes1);
      const enrollRes = await request(harness.app)
        .post(`${MFA_BASE}/enroll`)
        .set("Cookie", cookie);
      const { secret } = enrollRes.body;
      const code = generateTotpCode(secret);
      await request(harness.app)
        .post(`${MFA_BASE}/confirm`)
        .set("Cookie", cookie)
        .send({ secret, code });
      const loginRes2 = await login(harness.app, "mfa-verify-2@example.com");
      const { mfaToken } = loginRes2.body;
      const res = await request(harness.app)
        .post(`${MFA_BASE}/verify`)
        .send({ mfaToken, code });
      expect(res.status).toBe(200);
      expect(res.body.user.email).toBe("mfa-verify-2@example.com");
      const setCookie = res.headers["set-cookie"];
      expect(setCookie).toBeDefined();
    });

    it("invalidates token after 5 failed attempts", async () => {
      await activeUser(harness.app, harness, "mfa-verify-3@example.com");
      const loginRes1 = await login(harness.app, "mfa-verify-3@example.com");
      const cookie = cookieOf(loginRes1);
      const enrollRes = await request(harness.app)
        .post(`${MFA_BASE}/enroll`)
        .set("Cookie", cookie);
      const { secret } = enrollRes.body;
      const code = generateTotpCode(secret);
      await request(harness.app)
        .post(`${MFA_BASE}/confirm`)
        .set("Cookie", cookie)
        .send({ secret, code });
      const loginRes2 = await login(harness.app, "mfa-verify-3@example.com");
      const { mfaToken } = loginRes2.body;
      for (let i = 0; i < 4; i++) {
        const res = await request(harness.app)
          .post(`${MFA_BASE}/verify`)
          .send({ mfaToken, code: "000000" });
        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe("MFA_INVALID");
      }
      const res5 = await request(harness.app)
        .post(`${MFA_BASE}/verify`)
        .send({ mfaToken, code: "000000" });
      expect(res5.status).toBe(400);
      expect(res5.body.error.code).toBe("MFA_INVALID");
      const res6 = await request(harness.app)
        .post(`${MFA_BASE}/verify`)
        .send({ mfaToken, code });
      expect(res6.status).toBe(400);
      expect(res6.body.error.code).toBe("TOKEN_INVALID");
    });
  });

  describe("recovery codes", () => {
    it("single-use: valid on first attempt, invalid on second", async () => {
      await activeUser(harness.app, harness, "mfa-recovery-1@example.com");
      const loginRes1 = await login(harness.app, "mfa-recovery-1@example.com");
      const cookie = cookieOf(loginRes1);
      const enrollRes = await request(harness.app)
        .post(`${MFA_BASE}/enroll`)
        .set("Cookie", cookie);
      const { secret } = enrollRes.body;
      const code = generateTotpCode(secret);
      const confirmRes = await request(harness.app)
        .post(`${MFA_BASE}/confirm`)
        .set("Cookie", cookie)
        .send({ secret, code });
      const recoveryCode = confirmRes.body.recoveryCodes[0];
      const loginRes2 = await login(harness.app, "mfa-recovery-1@example.com");
      const { mfaToken } = loginRes2.body;
      const verifyRes = await request(harness.app)
        .post(`${MFA_BASE}/verify`)
        .send({ mfaToken, code: recoveryCode });
      expect(verifyRes.status).toBe(200);
      const loginRes3 = await login(harness.app, "mfa-recovery-1@example.com");
      const { mfaToken: mfaToken2 } = loginRes3.body;
      const verifyRes2 = await request(harness.app)
        .post(`${MFA_BASE}/verify`)
        .send({ mfaToken: mfaToken2, code: recoveryCode });
      expect(verifyRes2.status).toBe(400);
      expect(verifyRes2.body.error.code).toBe("MFA_INVALID");
    });
  });

  describe("disable", () => {
    it("rejects wrong code", async () => {
      await activeUser(harness.app, harness, "mfa-disable-1@example.com");
      const loginRes = await login(harness.app, "mfa-disable-1@example.com");
      const cookie = cookieOf(loginRes);
      const enrollRes = await request(harness.app)
        .post(`${MFA_BASE}/enroll`)
        .set("Cookie", cookie);
      const { secret } = enrollRes.body;
      const code = generateTotpCode(secret);
      await request(harness.app)
        .post(`${MFA_BASE}/confirm`)
        .set("Cookie", cookie)
        .send({ secret, code });
      const res = await request(harness.app)
        .post(`${MFA_BASE}/disable`)
        .set("Cookie", cookie)
        .send({ code: "000000" });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe("MFA_INVALID");
    });

    it("disables with correct code", async () => {
      await activeUser(harness.app, harness, "mfa-disable-2@example.com");
      const loginRes = await login(harness.app, "mfa-disable-2@example.com");
      const cookie = cookieOf(loginRes);
      const enrollRes = await request(harness.app)
        .post(`${MFA_BASE}/enroll`)
        .set("Cookie", cookie);
      const { secret } = enrollRes.body;
      const code = generateTotpCode(secret);
      await request(harness.app)
        .post(`${MFA_BASE}/confirm`)
        .set("Cookie", cookie)
        .send({ secret, code });
      const disableRes = await request(harness.app)
        .post(`${MFA_BASE}/disable`)
        .set("Cookie", cookie)
        .send({ code: generateTotpCode(secret) });
      expect(disableRes.status).toBe(204);
      const loginRes2 = await login(harness.app, "mfa-disable-2@example.com");
      expect(loginRes2.body.user).toBeDefined();
      expect(loginRes2.body.mfaRequired).toBeUndefined();
    });
  });
});
