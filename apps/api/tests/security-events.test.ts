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
import { createSessionRepository } from "../src/modules/session/session-repository.js";
import { createSessionService } from "../src/modules/session/session-service.js";
import { createOutboxRepository } from "../src/modules/email/outbox-repository.js";
import {
  createEmailService,
  type EmailMessage,
  type EmailProvider,
} from "../src/modules/email/email-service.js";
import { createSecurityEventRepository } from "../src/modules/security-events/security-events-repository.js";
import { createSecurityEventService } from "../src/modules/security-events/security-events-service.js";
import { describeDb, resetTestDatabase, TEST_DATABASE_URL, TEST_MFA_KEY } from "./helpers/db.js";
import { migrateToLatest } from "../src/infrastructure/db/migrate.js";
import { decryptSecret } from "../src/infrastructure/crypto/cipher.js";
import type { EncryptionKeyEntry } from "../src/infrastructure/config/config.js";

const PASSWORD = "Correct-horse-battery-staple-1";
const ORIGIN = "http://localhost:5173";
const BASE_URL = "/api/v1/auth";
const SERVICE_KEY = "test-service-api-key-123456";

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
    SERVICE_API_KEY: SERVICE_KEY,
  });
}

interface TestHarness {
  app: Express;
  db: Kysely<Database>;
  pool: { end(): Promise<void> };
  sessions: ReturnType<typeof createSessionService>;
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
  const securityEvents = createSecurityEventService(createSecurityEventRepository(db));
  const app = createApp({
    config,
    logger,
    db,
    hasher,
    limiter,
    users,
    sessions,
    tokens,
    emails,
    mfa,
    provider,
    keys: config.mfaEncryptionKeys,
    securityEvents,
  });
  return { app, db, pool, sessions, keys: config.mfaEncryptionKeys };
}

function cookieOf(res: request.Response): string {
  const setCookie = res.headers["set-cookie"];
  const raw = Array.isArray(setCookie) ? setCookie[0] : undefined;
  if (typeof raw !== "string") {
    throw new Error("no Set-Cookie header");
  }
  return raw.split(";")[0]!;
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

async function signup(harness: TestHarness, email: string): Promise<request.Response> {
  return request(harness.app)
    .post(`${BASE_URL}/signup`)
    .set("Origin", ORIGIN)
    .send({ email, password: PASSWORD });
}

async function login(harness: TestHarness, email: string, password: string = PASSWORD): Promise<request.Response> {
  return request(harness.app)
    .post(`${BASE_URL}/login`)
    .set("Origin", ORIGIN)
    .send({ email, password });
}

async function verifyEmail(harness: TestHarness, token: string): Promise<request.Response> {
  return request(harness.app).post(`${BASE_URL}/verify-email`).set("Origin", ORIGIN).send({ token });
}

async function signupAndVerifyEmail(harness: TestHarness, email: string): Promise<string> {
  const signupRes = await signup(harness, email);
  expect(signupRes.status).toBe(201);
  const message = await harness.db
    .selectFrom("email_outbox")
    .selectAll()
    .where("recipient", "=", email)
    .orderBy("id", "desc")
    .executeTakeFirstOrThrow();
  const token = tokenFromBody(unsealBody(message.body, harness.keys));
  const verifyRes = await verifyEmail(harness, token);
  expect(verifyRes.status).toBe(200);
  return signupRes.body.user.id as string;
}

async function eventsFor(
  db: Kysely<Database>,
  userId: string,
): Promise<{ event_type: string; actor: string }[]> {
  return db
    .selectFrom("security_events")
    .select(["event_type", "actor"])
    .where("user_id", "=", userId)
    .orderBy("occurred_at", "asc")
    .execute();
}

describeDb("security events", () => {
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

  it("records SIGNUP and EMAIL_VERIFIED when an account is created and verified", async () => {
    const email = "events-signup@example.com";
    const userId = await signupAndVerifyEmail(harness, email);
    const events = await eventsFor(harness.db, userId);
    expect(events.map((e) => e.event_type)).toEqual(["SIGNUP", "EMAIL_VERIFIED"]);

    const signupRow = await harness.db
      .selectFrom("security_events")
      .selectAll()
      .where("user_id", "=", userId)
      .where("event_type", "=", "SIGNUP")
      .executeTakeFirstOrThrow();
    expect(signupRow.actor).toBe("USER");
    expect(signupRow.ip_address).not.toBeNull();
    expect(signupRow.correlation_id).not.toBeNull();
    expect(signupRow.metadata).toEqual({});
  });

  it("records LOGIN_FAILURE and LOGIN_SUCCESS around a bad then good password", async () => {
    const email = "events-login@example.com";
    const userId = await signupAndVerifyEmail(harness, email);

    const badLogin = await login(harness, email, "wrong-password-123");
    expect(badLogin.status).toBe(401);
    expect(badLogin.body.error.code).toBe("INVALID_CREDENTIALS");

    const goodLogin = await login(harness, email);
    expect(goodLogin.status).toBe(200);
    expect(goodLogin.body.user.status).toBe("ACTIVE");

    const events = await eventsFor(harness.db, userId);
    const loginRelated = events.filter(
      (e) => e.event_type === "LOGIN_FAILURE" || e.event_type === "LOGIN_SUCCESS",
    );
    expect(loginRelated.map((e) => e.event_type)).toEqual(["LOGIN_FAILURE", "LOGIN_SUCCESS"]);
    expect(loginRelated.every((e) => e.actor === "USER")).toBe(true);
  });

  it("records SYSTEM-actor introspect events for accepted and rejected tokens", async () => {
    const email = "events-introspect@example.com";
    const userId = await signupAndVerifyEmail(harness, email);
    const { token } = await harness.sessions.createSession({ userId });

    const validRes = await request(harness.app)
      .post(`${BASE_URL}/introspect`)
      .set("Origin", ORIGIN)
      .set("X-Service-Key", SERVICE_KEY)
      .send({ sessionSecret: token });
    expect(validRes.status).toBe(200);
    expect(validRes.body).toMatchObject({ valid: true, status: "ACTIVE" });

    const rejectedRes = await request(harness.app)
      .post(`${BASE_URL}/introspect`)
      .set("Origin", ORIGIN)
      .set("X-Service-Key", SERVICE_KEY)
      .send({ sessionSecret: "definitely-not-a-real-secret" });
    expect(rejectedRes.status).toBe(200);
    expect(rejectedRes.body.valid).toBe(false);

    const successRows = await harness.db
      .selectFrom("security_events")
      .selectAll()
      .where("user_id", "=", userId)
      .where("event_type", "=", "INTROSPECT_SUCCESS")
      .execute();
    expect(successRows).toHaveLength(1);
    expect(successRows[0]!.actor).toBe("SYSTEM");

    const rejectedRows = await harness.db
      .selectFrom("security_events")
      .selectAll()
      .where("event_type", "=", "INTROSPECT_TOKEN_REJECTED")
      .execute();
    expect(rejectedRows).toHaveLength(1);
    expect(rejectedRows[0]!.actor).toBe("SYSTEM");
    expect(rejectedRows[0]!.user_id).toBeNull();
  });

  it("records ALL_SESSIONS_REVOKED and SESSION_REVOKED", async () => {
    const email = "events-sessions@example.com";
    const userId = await signupAndVerifyEmail(harness, email);

    const loginRes = await login(harness, email);
    const cookie = cookieOf(loginRes);

    const revokeAllRes = await request(harness.app)
      .post(`${BASE_URL}/sessions/revoke-all`)
      .set("Origin", ORIGIN)
      .set("Cookie", cookie);
    expect(revokeAllRes.status).toBe(204);

    const reloginRes = await login(harness, email);
    expect(reloginRes.status).toBe(200);
    const currentSession = await harness.db
      .selectFrom("sessions")
      .selectAll()
      .where("user_id", "=", userId)
      .where("revoked_at", "is", null)
      .orderBy("created_at", "desc")
      .executeTakeFirstOrThrow();

    const revokeRes = await request(harness.app)
      .delete(`${BASE_URL}/sessions/${currentSession.id}`)
      .set("Origin", ORIGIN)
      .set("Cookie", cookieOf(reloginRes));
    expect(revokeRes.status).toBe(204);

    const events = await eventsFor(harness.db, userId);
    const sessionEvents = events
      .filter(
        (e) => e.event_type === "ALL_SESSIONS_REVOKED" || e.event_type === "SESSION_REVOKED",
      )
      .map((e) => e.event_type);
    expect(sessionEvents).toEqual(["ALL_SESSIONS_REVOKED", "SESSION_REVOKED"]);
  });
});