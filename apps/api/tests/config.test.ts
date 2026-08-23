import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/infrastructure/config/config.js";
import { ConfigError } from "../src/shared/app-error.js";
import { TEST_DATABASE_URL, TEST_MFA_KEY } from "./helpers/db.js";

const BASE_ENV: NodeJS.ProcessEnv = {
  NODE_ENV: "test",
  DATABASE_URL: TEST_DATABASE_URL,
  FRONTEND_URL: "http://localhost:5173",
  AUTH_BASE_URL: "http://localhost:3000",
  MFA_ENCRYPTION_KEYS: TEST_MFA_KEY,
};

function load(overrides: NodeJS.ProcessEnv = {}): ReturnType<typeof loadConfig> {
  return loadConfig({ ...BASE_ENV, ...overrides });
}

describe("config", () => {
  it("loads a valid minimal test env", () => {
    const config = load();
    expect(config.nodeEnv).toBe("test");
    expect(config.rateLimiterBackend).toBe("memory");
    expect(config.rateLimits.loginIp).toEqual({ limit: 20, windowMs: 60_000 });
    expect(config.allowedOrigins).toEqual(["http://localhost:5173", "http://localhost:3000"]);
  });

  it("is frozen (deep)", () => {
    const config = load();
    expect(Object.isFrozen(config)).toBe(true);
    expect(Object.isFrozen(config.rateLimits)).toBe(true);
    expect(() => {
      // @ts-expect-error readonly by design
      config.port = 9999;
    }).toThrow();
  });

  it("fails fast when DATABASE_URL is missing", () => {
    const { DATABASE_URL: _removed, ...rest } = BASE_ENV;
    expect(() => loadConfig(rest)).toThrow(ConfigError);
  });

  it("fails fast when FRONTEND_URL is invalid", () => {
    expect(() => load({ FRONTEND_URL: "not-a-url" })).toThrow(ConfigError);
  });

  it("fails fast when ALLOWED_ORIGINS contains a non-URL entry", () => {
    expect(() => load({ ALLOWED_ORIGINS: "https://app.example.com,garbage" })).toThrow(ConfigError);
  });

  it("canonicalizes ALLOWED_ORIGINS entries to bare origins and dedupes preserving order", () => {
    const config = load({
      ALLOWED_ORIGINS:
        "HTTPS://App.Example.com:443/, https://app.example.com, http://other.example.com:80, https://api.example.com",
    });
    expect(config.allowedOrigins).toEqual([
      "https://app.example.com",
      "http://other.example.com",
      "https://api.example.com",
    ]);
  });

  it("leaves frontendUrl and authBaseUrl as configured (no canonicalization)", () => {
    const config = load({ FRONTEND_URL: "https://App.Example.com/", AUTH_BASE_URL: "https://Auth.Example.com/" });
    expect(config.frontendUrl).toBe("https://App.Example.com/");
    expect(config.authBaseUrl).toBe("https://Auth.Example.com/");
    expect(config.allowedOrigins).toEqual(["https://app.example.com", "https://auth.example.com"]);
  });

  it("defaults MFA_MAX_FAILED_ATTEMPTS and accepts overrides", () => {
    expect(load().mfaMaxFailedAttempts).toBe(5);
    expect(load({ MFA_MAX_FAILED_ATTEMPTS: "3" }).mfaMaxFailedAttempts).toBe(3);
    expect(() => load({ MFA_MAX_FAILED_ATTEMPTS: "0" })).toThrow(ConfigError);
  });

  it("fails fast when MFA_ENCRYPTION_KEYS is malformed", () => {
    expect(() => load({ MFA_ENCRYPTION_KEYS: "not-a-key-list" })).toThrow(ConfigError);
  });

  it("fails fast on duplicate key versions", () => {
    const key = Buffer.alloc(32, 1).toString("base64");
    const otherKey = Buffer.alloc(32, 2).toString("base64");
    expect(() => load({ MFA_ENCRYPTION_KEYS: `v1:${key},v1:${otherKey}` })).toThrow(ConfigError);
  });

  it("parses ordered key list newest-first", () => {
    const key = Buffer.alloc(32, 1).toString("base64");
    const otherKey = Buffer.alloc(32, 2).toString("base64");
    const config = load({ MFA_ENCRYPTION_KEYS: `v2:${key},v1:${otherKey}` });
    expect(config.mfaEncryptionKeys.map((e) => e.version)).toEqual([2, 1]);
  });

  it("accepts a base64-encoded AES-256 key", () => {
    const key = Buffer.from("k".repeat(32)).toString("base64");
    const config = load({ MFA_ENCRYPTION_KEYS: `v1:${key}` });
    expect(config.mfaEncryptionKeys).toEqual([{ version: 1, key }]);
  });

  it("rejects MFA encryption keys that are not valid base64", () => {
    expect(() => load({ MFA_ENCRYPTION_KEYS: "v1:!!not-base64!!" })).toThrow(/not valid base64/);
  });

  it("rejects MFA encryption keys that do not decode to 32 bytes", () => {
    const shortKey = Buffer.alloc(16, 1).toString("base64");
    expect(() => load({ MFA_ENCRYPTION_KEYS: `v1:${shortKey}` })).toThrow(
      /must decode to exactly 32 bytes/,
    );
  });

  it("fails fast on unknown rate limiter backend", () => {
    expect(() => load({ RATE_LIMITER_BACKEND: "file" })).toThrow(ConfigError);
  });

  it("rejects malformed RATE_LIMITS_JSON", () => {
    expect(() => load({ RATE_LIMITS_JSON: "{not json" })).toThrow(ConfigError);
    expect(() => load({ RATE_LIMITS_JSON: '{"bogus":{"limit":1,"windowMs":1000}}' })).toThrow(
      ConfigError,
    );
  });

  it("accepts RATE_LIMITS_JSON overrides", () => {
    const config = load({
      RATE_LIMITS_JSON: '{"loginIp":{"limit":5,"windowMs":60000},"signup":{"limit":1,"windowMs":1000}}',
    });
    expect(config.rateLimits.loginIp).toEqual({ limit: 5, windowMs: 60_000 });
    expect(config.rateLimits.signup).toEqual({ limit: 1, windowMs: 1000 });
    expect(config.rateLimits.me).toEqual({ limit: 60, windowMs: 60_000 });
  });

  it("defaults JWT issuer/audience to AUTH_BASE_URL", () => {
    const config = load();
    expect(config.jwtIssuer).toBe("http://localhost:3000");
    expect(config.jwtAudience).toBe("http://localhost:3000");
    expect(config.jwtAccessTtlSeconds).toBe(900);
  });

  it("accepts explicit JWT issuer/audience", () => {
    const config = load({ JWT_ISSUER: "https://auth.example.com", JWT_AUDIENCE: "https://api.example.com" });
    expect(config.jwtIssuer).toBe("https://auth.example.com");
    expect(config.jwtAudience).toBe("https://api.example.com");
  });

  it("defaults argon params to the centralized values", () => {
    const config = load();
    expect(config.argonMemoryKib).toBe(19_456);
    expect(config.argonTimeCost).toBe(2);
    expect(config.argonParallelism).toBe(1);
    expect(config.argonHashLength).toBe(32);
  });

  describe("production fail-fast", () => {
    const HARDENED: NodeJS.ProcessEnv = {
      NODE_ENV: "production",
      FRONTEND_URL: "https://localhost:5173",
      AUTH_BASE_URL: "https://localhost:3000",
      COOKIE_SECURE: "true",
      HTTPS_ENFORCED: "true",
      EMAIL_PROVIDER: "smtp",
      SMTP_URL: "smtps://user:pass@smtp.example.com:465",
      RATE_LIMITER_BACKEND: "redis",
      SERVICE_API_KEY: "0123456789abcdef",
      JWT_PRIVATE_KEY: "0123456789abcdef0123456789abcdef",
      JWT_KID: "prod-key-1",
    };

    it("refuses to start when prod-required secrets are missing", () => {
      expect(() => load({ NODE_ENV: "production" })).toThrow(/Refusing to start/);
    });

    it("refuses to start with insecure cookie flag", () => {
      expect(() => load({ ...HARDENED, COOKIE_SECURE: "false" })).toThrow(/COOKIE_SECURE=true/);
    });

    it("refuses to start with memory rate limiter in prod", () => {
      expect(() => load({ ...HARDENED, RATE_LIMITER_BACKEND: "memory" })).toThrow(
        /RATE_LIMITER_BACKEND=redis/,
      );
    });

  it("refuses to start with short service key in prod", () => {
    expect(() => load({ ...HARDENED, SERVICE_API_KEY: "short" })).toThrow(/SERVICE_API_KEY/);
  });

  it("refuses to start without JWT_KID in prod", () => {
    const { JWT_KID: _removed, ...rest } = HARDENED;
    expect(() => load(rest)).toThrow(/JWT_KID/);
  });

    it("accepts a fully hardened production env", () => {
      const config = load(HARDENED);
      expect(config.isProduction).toBe(true);
      expect(config.cookieSecure).toBe(true);
      expect(config.rateLimiterBackend).toBe("redis");
      expect(config.emailProvider).toBe("smtp");
    });

    it("refuses to start with an http FRONTEND_URL in prod", () => {
      expect(() => load({ ...HARDENED, FRONTEND_URL: "http://prod.example.com" })).toThrow(
        /Production environment requires HTTPS/,
      );
    });

    it("accepts an https FRONTEND_URL in prod", () => {
      const config = load({ ...HARDENED, FRONTEND_URL: "https://prod.example.com" });
      expect(config.frontendUrl).toBe("https://prod.example.com");
    });

    it("refuses to start with an http ALLOWED_ORIGINS entry in prod", () => {
      expect(() =>
        load({
          ...HARDENED,
          ALLOWED_ORIGINS: "https://app.example.com,http://insecure.example.com",
        }),
      ).toThrow(/Production environment requires HTTPS/);
    });
  });
});
