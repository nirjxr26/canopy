import { beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import { generateKeyPairSync } from "node:crypto";
import { jwtVerify, importSPKI } from "jose";
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
const ORIGIN = "http://localhost:5173";
const ISSUER = "http://localhost:3000";
const AUDIENCE = "auuth-api";

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const JWT_PRIVATE_KEY = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
const JWT_PUBLIC_PEM = publicKey.export({ type: "spki", format: "pem" }) as string;

function makeTestConfig() {
  return loadConfig({
    NODE_ENV: "test",
    DATABASE_URL: TEST_DATABASE_URL,
    FRONTEND_URL: ORIGIN,
    AUTH_BASE_URL: ISSUER,
    MFA_ENCRYPTION_KEYS: TEST_MFA_KEY,
    JWT_PRIVATE_KEY,
    JWT_KID: "test-key-1",
    JWT_ISSUER: ISSUER,
    JWT_AUDIENCE: AUDIENCE,
    JWT_ACCESS_TTL_SECONDS: "300",
  });
}

function makeHarness() {
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
  return { app, pool, users };
}

const PRIVATE_JWK_PARAMS = ["d", "p", "q", "dp", "dq", "qi", "oth"];

describeDb("JWT issuing (tokens) and JWKS", () => {
  beforeAll(async () => {
    await resetTestDatabase();
    await migrateToLatest({ databaseUrl: TEST_DATABASE_URL, dbPoolMin: 2, dbPoolMax: 10 });
  });

  it("GET /.well-known/jwks.json exposes only public key parameters", async () => {
    const { app, pool } = makeHarness();
    try {
      const res = await request(app).get("/.well-known/jwks.json");
      expect(res.status).toBe(200);
      const { keys } = res.body;
      expect(Array.isArray(keys)).toBe(true);
      expect(keys).toHaveLength(1);
      const key = keys[0];
      expect(key.kid).toBe("test-key-1");
      expect(key.kty).toBe("RSA");
      expect(key.alg).toBe("RS256");
      expect(key.use).toBe("sig");
      expect(typeof key.n).toBe("string");
      expect(typeof key.e).toBe("string");
      for (const param of PRIVATE_JWK_PARAMS) {
        expect(key[param]).toBeUndefined();
      }
      expect(JSON.stringify(res.body)).not.toMatch(/"d"\s*:/);
    } finally {
      await pool.end();
    }
  });

  it("POST /api/v1/auth/tokens requires an authenticated session", async () => {
    const { app, pool } = makeHarness();
    try {
      const res = await request(app).post("/api/v1/auth/tokens").set("Origin", ORIGIN);
      expect(res.status).toBe(401);
    } finally {
      await pool.end();
    }
  });

  it("POST /api/v1/auth/tokens mints a verifiable RS256 access token for the session user", async () => {
    const { app, pool, users } = makeHarness();
    try {
      const signupRes = await request(app)
        .post("/api/v1/auth/signup")
        .set("Origin", ORIGIN)
        .send({ email: "jwt-mint@example.com", password: PASSWORD });
      expect(signupRes.status).toBe(201);
      const user = await users.findByEmail("jwt-mint@example.com");
      await users.verifyEmail(user!.id);

      const loginRes = await request(app)
        .post("/api/v1/auth/login")
        .set("Origin", ORIGIN)
        .send({ email: "jwt-mint@example.com", password: PASSWORD });
      expect(loginRes.status).toBe(200);
      const cookie = loginRes.headers["set-cookie"][0].split(";")[0];

      const res = await request(app)
        .post("/api/v1/auth/tokens")
        .set("Origin", ORIGIN)
        .set("Cookie", cookie);
      expect(res.status).toBe(200);
      expect(res.body.tokenType).toBe("Bearer");
      expect(res.body.expiresIn).toBe(300);

      const publicKey = await importSPKI(JWT_PUBLIC_PEM, "RS256");
      const { payload } = await jwtVerify(res.body.accessToken, publicKey, {
        issuer: ISSUER,
        audience: AUDIENCE,
      });
      expect(payload.sub).toBe(user!.id);
      expect(payload.email).toBe("jwt-mint@example.com");
      expect(payload.email_verified).toBe(true);
      expect(payload.status).toBe("ACTIVE");
    } finally {
      await pool.end();
    }
  });
});