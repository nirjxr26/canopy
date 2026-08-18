import { beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import pg from "pg";
import { Kysely, PostgresDialect } from "kysely";
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
import { describeDb, TEST_DATABASE_URL, TEST_MFA_KEY } from "./helpers/db.js";
import { migrateToLatest } from "../src/infrastructure/db/migrate.js";

function makeTestConfig() {
  return loadConfig({
    NODE_ENV: "test",
    DATABASE_URL: TEST_DATABASE_URL,
    FRONTEND_URL: "http://localhost:5173",
    AUTH_BASE_URL: "http://localhost:3000",
    MFA_ENCRYPTION_KEYS: TEST_MFA_KEY,
  });
}

function buildApp(config: ReturnType<typeof makeTestConfig>, db: Kysely<Database>) {
  const logger = createLogger("silent");
  const hasher = createPasswordHasher({ memoryCostKiB: 8192, timeCost: 1, parallelism: 1, hashLength: 32 });
  const limiter = new InMemoryRateLimiter();
  const users = createUserService(createUserRepository(db), hasher);
  const sessions = createSessionService(createSessionRepository(db), { getById: users.getById }, config);
  const tokens = createTokenService(createTokenRepository(db));
  const mfa = createMfaService({ repository: createMfaRepository(db), tokens, db, keys: config.mfaEncryptionKeys, issuer: config.jwtIssuer });
  const provider = { kind: "console" as const, send: async () => {} };
  const emails = createEmailService({ outbox: createOutboxRepository(db), provider, config, keys: config.mfaEncryptionKeys, logger });
  return createApp({ config, logger, db, hasher, limiter, users, sessions, tokens, emails, mfa, provider, keys: config.mfaEncryptionKeys });
}

async function withApp(
  config: ReturnType<typeof makeTestConfig>,
  run: (app: ReturnType<typeof createApp>) => Promise<void>,
): Promise<void> {
  const { db, pool } = createDb(config);
  try {
    await run(buildApp(config, db));
  } finally {
    await pool.end();
  }
}

describe("app basics", () => {
  const config = makeTestConfig();

  it("returns X-Request-Id on every response", async () => {
    await withApp(config, async (app) => {
      const res = await request(app).get("/healthz").set("X-Request-Id", "my-custom-id-123");
      expect(res.header["x-request-id"]).toBe("my-custom-id-123");
    });
  });

  it("generates a request id when none is supplied", async () => {
    await withApp(config, async (app) => {
      const res = await request(app).get("/healthz");
      expect(res.header["x-request-id"]).toMatch(/^[\w.-]{8,64}$/);
    });
  });

  it("shapes unknown routes as the documented error envelope", async () => {
    await withApp(config, async (app) => {
      const res = await request(app).get("/api/v1/nope");
      expect(res.status).toBe(404);
      expect(res.body).toMatchObject({
        error: { code: "NOT_FOUND", message: "Not found" },
      });
      expect(typeof res.body.error.requestId).toBe("string");
    });
  });

  it("maps malformed JSON to a 400 VALIDATION error", async () => {
    await withApp(config, async (app) => {
      const res = await request(app)
        .post("/api/v1/auth/login")
        .set("Content-Type", "application/json")
        .send("{not json");
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe("VALIDATION");
    });
  });

  it("never leaks stack traces or internals", async () => {
    await withApp(config, async (app) => {
      const res = await request(app)
        .post("/api/v1/auth/login")
        .set("Content-Type", "application/json")
        .send("{broken");
      const body = JSON.stringify(res.body);
      expect(body).not.toContain("at ");
      expect(body).not.toContain("Error");
    });
  });
});

describe("HTTPS enforcement", () => {
  it("rejects plain HTTP with HTTPS_REQUIRED when HTTPS_ENFORCED is set", async () => {
    const config = loadConfig({
      NODE_ENV: "test",
      DATABASE_URL: TEST_DATABASE_URL,
      FRONTEND_URL: "http://localhost:5173",
      AUTH_BASE_URL: "http://localhost:3000",
      MFA_ENCRYPTION_KEYS: TEST_MFA_KEY,
      HTTPS_ENFORCED: "true",
    });
    await withApp(config, async (app) => {
      const res = await request(app).get("/api/v1/nope");
      expect(res.status).toBe(403);
      expect(res.body).toMatchObject({
        error: { code: "HTTPS_REQUIRED", message: "HTTPS is required" },
      });
    });
  });

  it("accepts X-Forwarded-Proto: https when TRUST_PROXY is set", async () => {
    const config = loadConfig({
      NODE_ENV: "test",
      DATABASE_URL: TEST_DATABASE_URL,
      FRONTEND_URL: "http://localhost:5173",
      AUTH_BASE_URL: "http://localhost:3000",
      MFA_ENCRYPTION_KEYS: TEST_MFA_KEY,
      HTTPS_ENFORCED: "true",
      TRUST_PROXY: "1",
    });
    await withApp(config, async (app) => {
      const res = await request(app).get("/api/v1/nope").set("X-Forwarded-Proto", "https");
      expect(res.status).toBe(404);
      expect(res.body).toMatchObject({ error: { code: "NOT_FOUND", message: "Not found" } });
    });
  });

  it("does not enforce HTTPS by default", async () => {
    await withApp(makeTestConfig(), async (app) => {
      const res = await request(app).get("/api/v1/nope");
      expect(res.status).toBe(404);
      expect(res.body).toMatchObject({ error: { code: "NOT_FOUND", message: "Not found" } });
    });
  });
});

describeDb("healthz with database", () => {
  beforeAll(async () => {
    await migrateToLatest({ databaseUrl: TEST_DATABASE_URL, dbPoolMin: 2, dbPoolMax: 10 });
  });

  it("reports ok when the db is reachable", async () => {
    const config = makeTestConfig();
    const { db, pool } = createDb(config);
    const app = buildApp(config, db);
    try {
      const res = await request(app).get("/healthz");
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: "ok", db: "up" });
    } finally {
      await pool.end();
    }
  });

  it("reports degraded when the db is unreachable", async () => {
    const config = loadConfig({
      NODE_ENV: "test",
      DATABASE_URL: "postgres://postgres:postgres@localhost:59999/auuth_test",
      FRONTEND_URL: "http://localhost:5173",
      AUTH_BASE_URL: "http://localhost:3000",
      MFA_ENCRYPTION_KEYS: TEST_MFA_KEY,
    });
    const pool = new pg.Pool({
      connectionString: config.databaseUrl,
      connectionTimeoutMillis: 1500,
      max: 1,
    });
    const db = new Kysely<Database>({ dialect: new PostgresDialect({ pool }) });
    const app = buildApp(config, db);
    try {
      const res = await request(app).get("/healthz");
      expect(res.status).toBe(503);
      expect(res.body.status).toBe("degraded");
    } finally {
      await pool.end();
    }
  });
});
