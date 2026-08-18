import { beforeAll, beforeEach, afterEach, expect, it } from "vitest";
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
import { createEmailService } from "../src/modules/email/email-service.js";
import { createSessionRepository } from "../src/modules/session/session-repository.js";
import { createSessionService } from "../src/modules/session/session-service.js";
import { describeDb, resetTestDatabase, TEST_DATABASE_URL, TEST_MFA_KEY } from "./helpers/db.js";
import { migrateToLatest } from "../src/infrastructure/db/migrate.js";

const PASSWORD = "Correct-horse-battery-staple-1";
const BASE_URL = "/api/v1/auth";

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
    SESSION_IDLE_HOURS: "1",
    MAX_ACTIVE_SESSIONS: "3",
  });
}

interface TestHarness {
  app: Express;
  db: Kysely<Database>;
  pool: { end(): Promise<void> };
  users: ReturnType<typeof createUserService>;
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
  const provider = { kind: "console" as const, send: async () => {} };
  const emails = createEmailService({
    outbox: createOutboxRepository(db),
    provider,
    config,
    keys: config.mfaEncryptionKeys,
    logger,
  });
  const app = createApp({ config, logger, db, hasher, limiter, users, sessions, tokens, emails, mfa, provider, keys: config.mfaEncryptionKeys });
  return { app, db, pool, users };
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

async function activeUser(harness: TestHarness, email: string) {
  await signup(harness.app, email);
  const user = await harness.users.findByEmail(email);
  await harness.users.verifyEmail(user!.id);
  return user!;
}

describeDb("session policy", () => {
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

  it("invalidates a session idle beyond sessionIdleHours", async () => {
    const email = "session-policy-idle@example.com";
    await activeUser(harness, email);
    const loginRes = await login(harness.app, email);
    const cookie = cookieOf(loginRes);
    const row = await harness.db
      .selectFrom("sessions")
      .innerJoin("users", "users.id", "sessions.user_id")
      .select("sessions.id")
      .where("users.email", "=", email)
      .executeTakeFirstOrThrow();
    await harness.db
      .updateTable("sessions")
      .set({ last_used_at: new Date(Date.now() - 2 * 3_600_000) })
      .where("id", "=", row.id)
      .execute();
    const res = await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookie);
    expect(res.status).toBe(401);
  });

  it("keeps a recently used session valid", async () => {
    const email = "session-policy-active@example.com";
    await activeUser(harness, email);
    const loginRes = await login(harness.app, email);
    const cookie = cookieOf(loginRes);
    const res = await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookie);
    expect(res.status).toBe(200);
  });

  it("evicts the oldest non-revoked sessions beyond maxActiveSessions", async () => {
    const email = "session-policy-cap@example.com";
    await activeUser(harness, email);
    const cookies: string[] = [];
    for (let i = 0; i < 4; i++) {
      cookies.push(cookieOf(await login(harness.app, email)));
    }
    const list = await request(harness.app).get(`${BASE_URL}/sessions`).set("Cookie", cookies[3]!);
    expect(list.status).toBe(200);
    expect(list.body.sessions).toHaveLength(3);
    const oldest = await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookies[0]!);
    expect(oldest.status).toBe(401);
    const newest = await request(harness.app).get(`${BASE_URL}/me`).set("Cookie", cookies[3]!);
    expect(newest.status).toBe(200);
  });
});