import { beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { createApp } from "../src/app/app.js";
import { loadConfig } from "../src/infrastructure/config/config.js";
import { createLogger } from "../src/infrastructure/logging/logger.js";
import { createDb } from "../src/infrastructure/db/database.js";
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
const SERVICE_KEY = "test-service-api-key-123456";

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

describeDb("Session Introspection & Consumer Integration API", () => {
  beforeAll(async () => {
    await resetTestDatabase();
    await migrateToLatest({ databaseUrl: TEST_DATABASE_URL, dbPoolMin: 2, dbPoolMax: 10 });
  });

  it("POST /api/v1/auth/introspect validates session secret for consumer middleware", async () => {
    const config = makeTestConfig();
    const logger = createLogger("silent");
    const { db, pool } = createDb(config);
    const hasher = createPasswordHasher({ memoryCostKiB: 8192, timeCost: 1, parallelism: 1, hashLength: 32 });
    const limiter = new InMemoryRateLimiter();
    const users = createUserService(createUserRepository(db), hasher);
    const sessions = createSessionService(createSessionRepository(db), { getById: users.getById }, config);
    const tokens = createTokenService(createTokenRepository(db));
    const mfa = createMfaService({ repository: createMfaRepository(db), tokens, db, keys: config.mfaEncryptionKeys, issuer: config.jwtIssuer });
    const emails = createEmailService({ outbox: createOutboxRepository(db), provider: { kind: "console", send: async () => {} }, config, keys: config.mfaEncryptionKeys, logger });

    const app = createApp({ config, logger, db, hasher, limiter, users, sessions, tokens, emails, mfa, provider: { kind: "console", send: async () => {} }, keys: config.mfaEncryptionKeys });

    try {
      // 1. Create and verify user
      const userRes = await users.register({ email: "introspect-consumer@example.com", password: PASSWORD });
      await users.verifyEmail(userRes.user!.id);
      const { token } = await sessions.createSession({ userId: userRes.user!.id });

      // 2. Introspect with valid service key
      const validRes = await request(app)
        .post("/api/v1/auth/introspect")
        .set("Origin", "http://localhost:3000")
        .set("X-Service-Key", SERVICE_KEY)
        .send({ sessionSecret: token });

      expect(validRes.status).toBe(200);
      expect(validRes.body.valid).toBe(true);
      expect(validRes.body.userId).toBe(userRes.user!.id);
      expect(validRes.body.email).toBe("introspect-consumer@example.com");

      // 3. Introspect with invalid service key -> 401
      const invalidKeyRes = await request(app)
        .post("/api/v1/auth/introspect")
        .set("Origin", "http://localhost:3000")
        .set("X-Service-Key", "wrong-key")
        .send({ sessionSecret: token });

      expect(invalidKeyRes.status).toBe(401);

      // 4. Introspect with invalid secret -> valid: false
      const invalidSecretRes = await request(app)
        .post("/api/v1/auth/introspect")
        .set("Origin", "http://localhost:3000")
        .set("X-Service-Key", SERVICE_KEY)
        .send({ sessionSecret: "invalid-secret" });

      expect(invalidSecretRes.status).toBe(200);
      expect(invalidSecretRes.body.valid).toBe(false);
    } finally {
      await pool.end();
    }
  });
});
