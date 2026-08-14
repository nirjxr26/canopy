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
import { createSessionRepository } from "../src/modules/session/session-repository.js";
import { createSessionService } from "../src/modules/session/session-service.js";
import { createOutboxRepository } from "../src/modules/email/outbox-repository.js";
import {
  createEmailService,
  type EmailMessage,
  type EmailProvider,
} from "../src/modules/email/email-service.js";
import { describeDb, resetTestDatabase, TEST_DATABASE_URL, TEST_MFA_KEY } from "./helpers/db.js";
import { migrateToLatest } from "../src/infrastructure/db/migrate.js";
import { decryptSecret } from "../src/infrastructure/crypto/cipher.js";
import type { EncryptionKeyEntry } from "../src/infrastructure/config/config.js";

const PASSWORD = "Correct-horse-battery-staple-1";
const NEW_PASSWORD = "New-correct-horse-battery-staple-2";
const ORIGIN = "http://localhost:5173";
const BASE_URL = "/api/v1/auth";

class RecordingProvider implements EmailProvider {
  readonly kind = "console" as const;
  readonly sent: EmailMessage[] = [];
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
  keys: readonly EncryptionKeyEntry[];
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
  return { app, db, pool, users, provider, keys: config.mfaEncryptionKeys };
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
    .set("Origin", ORIGIN)
    .send({ email, password: PASSWORD });
}

async function login(
  app: Express,
  email: string,
  password: string = PASSWORD,
): Promise<request.Response> {
  return request(app)
    .post(`${BASE_URL}/login`)
    .set("Origin", ORIGIN)
    .send({ email, password });
}

async function resend(app: Express, email: string): Promise<request.Response> {
  return request(app).post(`${BASE_URL}/resend-verification`).set("Origin", ORIGIN).send({ email });
}

async function forgot(app: Express, email: string): Promise<request.Response> {
  return request(app).post(`${BASE_URL}/forgot-password`).set("Origin", ORIGIN).send({ email });
}

async function verifyEmail(app: Express, token: string): Promise<request.Response> {
  return request(app).post(`${BASE_URL}/verify-email`).set("Origin", ORIGIN).send({ token });
}

async function resetPassword(
  app: Express,
  token: string,
  newPassword: string,
): Promise<request.Response> {
  return request(app)
    .post(`${BASE_URL}/reset-password`)
    .set("Origin", ORIGIN)
    .send({ token, newPassword });
}

function tokenFromBody(body: string): string {
  const match = /token=([A-Za-z0-9_-]+)/.exec(body);
  if (match === null) {
    throw new Error("no token found in email body");
  }
  return match[1]!;
}

function unsealBody(body: string, keys: readonly EncryptionKeyEntry[]): string {
  const parsed = JSON.parse(decryptSecret(body, keys)) as { text: string };
  return parsed.text;
}

describeDb("verification & recovery endpoints", () => {
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

  async function pendingUser(email: string): Promise<{ token: string }> {
    await signup(harness.app, email);
    const message = await harness.db
      .selectFrom("email_outbox")
      .selectAll()
      .where("recipient", "=", email)
      .orderBy("id", "desc")
      .executeTakeFirstOrThrow();
    return { token: tokenFromBody(unsealBody(message.body, harness.keys)) };
  }

  describe("verify-email", () => {
    it("queues a verification email on signup", async () => {
      const email = "verify-signup-email@example.com";
      const res = await signup(harness.app, email);
      expect(res.status).toBe(201);
      const message = await harness.db
        .selectFrom("email_outbox")
        .selectAll()
        .where("recipient", "=", email)
        .executeTakeFirstOrThrow();
      expect(message.subject).toBe("Verify your email");
      const token = tokenFromBody(unsealBody(message.body, harness.keys));
      const activated = await verifyEmail(harness.app, token);
      expect(activated.status).toBe(200);
    });

    it("activates a pending account and consumes the token", async () => {
      const email = "verify-ok@example.com";
      await signup(harness.app, email);
      const raw = (await pendingUser(email)).token;
      const res = await verifyEmail(harness.app, raw);
      expect(res.status).toBe(200);
      expect(res.body.user).toMatchObject({ email, status: "ACTIVE", emailVerified: true });
      const user = await harness.users.findByEmail(email);
      expect(user!.status).toBe("ACTIVE");
      expect(user!.emailVerifiedAt).not.toBeNull();
    });

    it("rejects a used token", async () => {
      const email = "verify-reuse@example.com";
      await signup(harness.app, email);
      const raw = (await pendingUser(email)).token;
      const first = await verifyEmail(harness.app, raw);
      expect(first.status).toBe(200);
      const second = await verifyEmail(harness.app, raw);
      expect(second.status).toBe(400);
      expect(second.body.error.code).toBe("TOKEN_INVALID");
    });

    it("rejects an expired token", async () => {
      const email = "verify-expired@example.com";
      await signup(harness.app, email);
      const raw = (await pendingUser(email)).token;
      const user = await harness.users.findByEmail(email);
      await harness.db
        .updateTable("tokens")
        .set({ expires_at: new Date(Date.now() - 60_000) })
        .where("user_id", "=", user!.id)
        .execute();
      const res = await verifyEmail(harness.app, raw);
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe("TOKEN_INVALID");
    });

    it("rejects an unknown token", async () => {
      const res = await verifyEmail(harness.app, "garbage-token");
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe("TOKEN_INVALID");
    });
  });

  describe("resend-verification", () => {
    it("queues a fresh verification email for a pending account", async () => {
      const email = "resend-1@example.com";
      await signup(harness.app, email);
      const res = await resend(harness.app, email);
      expect(res.status).toBe(200);
      expect(res.body.devEmailLink).toContain("verify-email?token=");
      const user = await harness.users.findByEmail(email);
      const message = await harness.db
        .selectFrom("email_outbox")
        .selectAll()
        .where("recipient", "=", email)
        .executeTakeFirstOrThrow();
      expect(message.subject).toBe("Verify your email");
      expect(message.body).not.toContain("verify-email?token=");
      expect(unsealBody(message.body, harness.keys)).toContain("verify-email?token=");
      const tokenRow = await harness.db
        .selectFrom("tokens")
        .selectAll()
        .where("user_id", "=", user!.id)
        .where("kind", "=", "EMAIL_VERIFICATION")
        .executeTakeFirstOrThrow();
      expect(tokenRow.used_at).toBeNull();
    });

    it("is generic for unknown emails (200, no rows)", async () => {
      const res = await resend(harness.app, "ghost@example.com");
      expect(res.status).toBe(200);
      expect(res.body).toEqual({});
      const rows = await harness.db
        .selectFrom("email_outbox")
        .selectAll()
        .where("recipient", "=", "ghost@example.com")
        .execute();
      expect(rows).toHaveLength(0);
    });

    it("is generic for already-verified accounts (no new email)", async () => {
      const email = "resend-verified@example.com";
      const raw = (await pendingUser(email)).token;
      await verifyEmail(harness.app, raw);
      const before = await harness.db
        .selectFrom("email_outbox")
        .selectAll()
        .where("recipient", "=", email)
        .execute();
      expect(before).toHaveLength(1);
      await resend(harness.app, email);
      const rows = await harness.db
        .selectFrom("email_outbox")
        .selectAll()
        .where("recipient", "=", email)
        .execute();
      expect(rows).toHaveLength(1);
    });

    it("rate limits per email (3/h → 429)", async () => {
      const email = "resend-limited@example.com";
      const statuses: number[] = [];
      for (let i = 0; i < 4; i++) {
        statuses.push((await resend(harness.app, email)).status);
      }
      expect(statuses).toEqual([200, 200, 200, 429]);
    });
  });

  describe("forgot-password", () => {
    async function activeUser(email: string) {
      await signup(harness.app, email);
      const raw = (await pendingUser(email)).token;
      await verifyEmail(harness.app, raw);
    }

    it("queues a reset email for an active account", async () => {
      const email = "forgot-1@example.com";
      await activeUser(email);
      const res = await forgot(harness.app, email);
      expect(res.status).toBe(200);
      expect(res.body.devEmailLink).toContain("reset-password?token=");
      const user = await harness.users.findByEmail(email);
      const message = await harness.db
        .selectFrom("email_outbox")
        .selectAll()
        .where("recipient", "=", email)
        .orderBy("id", "desc")
        .executeTakeFirstOrThrow();
      expect(message.subject).toBe("Reset your password");
      const tokenRow = await harness.db
        .selectFrom("tokens")
        .selectAll()
        .where("user_id", "=", user!.id)
        .where("kind", "=", "PASSWORD_RESET")
        .executeTakeFirstOrThrow();
      expect(tokenRow.used_at).toBeNull();
    });

    it("is generic for unknown emails (200, no rows)", async () => {
      const res = await forgot(harness.app, "ghost@example.com");
      expect(res.status).toBe(200);
      expect(res.body).toEqual({});
      const rows = await harness.db
        .selectFrom("email_outbox")
        .selectAll()
        .where("recipient", "=", "ghost@example.com")
        .execute();
      expect(rows).toHaveLength(0);
    });

    it("does not email pending accounts", async () => {
      const email = "forgot-pending@example.com";
      await signup(harness.app, email);
      const res = await forgot(harness.app, email);
      expect(res.status).toBe(200);
      expect(res.body).toEqual({});
      const rows = await harness.db
        .selectFrom("email_outbox")
        .selectAll()
        .where("recipient", "=", email)
        .where("subject", "=", "Reset your password")
        .execute();
      expect(rows).toHaveLength(0);
    });
  });

  describe("reset-password", () => {
    async function resetTokenFor(email: string): Promise<string> {
      await forgot(harness.app, email);
      const message = await harness.db
        .selectFrom("email_outbox")
        .selectAll()
        .where("recipient", "=", email)
        .orderBy("id", "desc")
        .executeTakeFirstOrThrow();
      return tokenFromBody(unsealBody(message.body, harness.keys));
    }

    async function activeUser(email: string) {
      await signup(harness.app, email);
      const raw = (await pendingUser(email)).token;
      await verifyEmail(harness.app, raw);
    }

    it("resets the password and revokes all sessions", async () => {
      const email = "reset-1@example.com";
      await activeUser(email);
      const cookieA = cookieOf(await login(harness.app, email));
      const cookieB = cookieOf(await login(harness.app, email));
      const token = await resetTokenFor(email);
      const res = await resetPassword(harness.app, token, NEW_PASSWORD);
      expect(res.status).toBe(200);
      expect(res.body.user.email).toBe(email);
      const meA = await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookieA);
      const meB = await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookieB);
      expect(meA.status).toBe(401);
      expect(meB.status).toBe(401);
      const oldLogin = await login(harness.app, email, PASSWORD);
      expect(oldLogin.status).toBe(401);
      const newLogin = await login(harness.app, email, NEW_PASSWORD);
      expect(newLogin.status).toBe(200);
    });

    it("rejects a used token", async () => {
      const email = "reset-reuse@example.com";
      await activeUser(email);
      const token = await resetTokenFor(email);
      const first = await resetPassword(harness.app, token, NEW_PASSWORD);
      expect(first.status).toBe(200);
      const second = await resetPassword(harness.app, token, NEW_PASSWORD);
      expect(second.status).toBe(400);
      expect(second.body.error.code).toBe("TOKEN_INVALID");
    });

    it("rejects an expired token", async () => {
      const email = "reset-expired@example.com";
      await activeUser(email);
      const token = await resetTokenFor(email);
      const user = await harness.users.findByEmail(email);
      await harness.db
        .updateTable("tokens")
        .set({ expires_at: new Date(Date.now() - 60_000) })
        .where("user_id", "=", user!.id)
        .execute();
      const res = await resetPassword(harness.app, token, NEW_PASSWORD);
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe("TOKEN_INVALID");
    });

    it("rejects a weak password without burning the token", async () => {
      const email = "reset-weak@example.com";
      await activeUser(email);
      const token = await resetTokenFor(email);
      const weak = await resetPassword(harness.app, token, "short");
      expect(weak.status).toBe(400);
      expect(weak.body.error.code).toBe("VALIDATION");
      const retry = await resetPassword(harness.app, token, NEW_PASSWORD);
      expect(retry.status).toBe(200);
    });
  });

  describe("change-password", () => {
    async function activeSession(email: string): Promise<string> {
      await signup(harness.app, email);
      const raw = (await pendingUser(email)).token;
      await verifyEmail(harness.app, raw);
      return cookieOf(await login(harness.app, email));
    }

    async function changePassword(
      cookie: string,
      currentPassword: string,
      newPassword: string,
    ): Promise<request.Response> {
      return request(harness.app)
        .post(`${BASE_URL}/change-password`)
        .set("Origin", ORIGIN)
        .set("Cookie", cookie)
        .send({ currentPassword, newPassword });
    }

    it("rejects a wrong current password", async () => {
      const cookie = await activeSession("change-1@example.com");
      const res = await changePassword(cookie, "wrong-password-1234", NEW_PASSWORD);
      expect(res.status).toBe(401);
      expect(res.body.error.code).toBe("INVALID_CREDENTIALS");
    });

    it("changes the password and revokes other sessions", async () => {
      const email = "change-2@example.com";
      const cookieA = await activeSession(email);
      const cookieB = cookieOf(await login(harness.app, email));
      const res = await changePassword(cookieA, PASSWORD, NEW_PASSWORD);
      expect(res.status).toBe(204);
      const meA = await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookieA);
      const meB = await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookieB);
      expect(meA.status).toBe(200);
      expect(meB.status).toBe(401);
      const oldLogin = await login(harness.app, email, PASSWORD);
      expect(oldLogin.status).toBe(401);
      const newLogin = await login(harness.app, email, NEW_PASSWORD);
      expect(newLogin.status).toBe(200);
    });

    it("rejects a weak new password", async () => {
      const cookie = await activeSession("change-3@example.com");
      const res = await changePassword(cookie, PASSWORD, "short");
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe("VALIDATION");
    });
  });
});
