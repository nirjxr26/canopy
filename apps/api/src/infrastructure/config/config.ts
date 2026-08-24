import { z } from "zod";
import { Buffer } from "node:buffer";
import { ConfigError } from "../../shared/app-error.js";
import { parseRateLimits, type RateLimitName, type RateLimitSpec } from "./rate-limits.js";

const boolFromString = z.preprocess((v) => {
  if (typeof v === "boolean") return v;
  if (v === "true" || v === "1") return true;
  if (v === "false" || v === "0") return false;
  return v;
}, z.boolean());

const intFrom = (min: number, max?: number) =>
  z.preprocess(
    (v) => (typeof v === "number" ? v : Number(v)),
    max === undefined
      ? z.int({ error: "expected a number" }).min(min)
      : z.int({ error: "expected a number" }).min(min).max(max),
  );

const keyList = z.string().min(1);

const urlString = z.string().min(1).refine((s) => {
  try {
    new URL(s);
    return true;
  } catch {
    return false;
  }
});

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: intFrom(1).default(3000),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
  TRUST_PROXY: intFrom(0).default(0),
  HTTPS_ENFORCED: boolFromString.default(false),
  RUN_MIGRATIONS_ON_BOOT: boolFromString.default(false),
  DATABASE_URL: z.string().min(1),
  DB_POOL_MIN: intFrom(0).default(2),
  DB_POOL_MAX: intFrom(1).default(10),
  FRONTEND_URL: urlString,
  AUTH_BASE_URL: urlString,
  ALLOWED_ORIGINS: z.string().optional(),
  COOKIE_DOMAIN: z.string().optional(),
  COOKIE_SECURE: boolFromString.default(false),
  SESSION_EXPIRY_DAYS: intFrom(1, 90).default(30),
  SESSION_IDLE_HOURS: intFrom(1, 720).default(12),
  MAX_ACTIVE_SESSIONS: intFrom(1, 100).default(5),
  SESSION_SECRET: z.string().optional(),
  MFA_ENCRYPTION_KEYS: keyList,
  ARGON_MEMORY_KIB: intFrom(1).default(19456),
  ARGON_TIME_COST: intFrom(1).default(2),
  ARGON_PARALLELISM: intFrom(1).default(1),
  ARGON_HASH_LENGTH: intFrom(16, 64).default(32),
  RATE_LIMITER_BACKEND: z.enum(["memory", "redis"]).default("memory"),
  REDIS_URL: z.string().min(1).default("redis://localhost:6379"),
  RATE_LIMITS_JSON: z.string().optional(),
  LOCK_DURATION_MIN: intFrom(1).default(15),
  MFA_MAX_FAILED_ATTEMPTS: intFrom(1).default(5),
  SERVICE_API_KEYS: z.string().optional(),
  BREACHED_PASSWORD_CHECKER: z.enum(["local", "hibp"]).optional(),
  WEB_DIST_DIR: z.string().optional(),
  JWT_PRIVATE_KEY: z.string().optional(),
  JWT_ISSUER: z.string().min(1).optional(),
  JWT_AUDIENCE: z.string().min(1).optional(),
  JWT_KID: z.string().optional(),
  JWT_ACCESS_TTL_SECONDS: intFrom(60).default(900),
  EMAIL_PROVIDER: z.enum(["console", "smtp"]).default("console"),
  EMAIL_FROM: z.string().min(1).default("no-reply@localhost"),
  SMTP_URL: z.string().optional(),
  EMAIL_RETRY_MAX: intFrom(1).default(5),
  EMAIL_RETRY_BACKOFF_MS: intFrom(1).default(30_000),
  RETENTION_DAYS: intFrom(1).default(90),
});

export interface EncryptionKeyEntry {
  version: number;
  key: string;
}

export interface Config {
  readonly nodeEnv: "development" | "test" | "production";
  readonly isProduction: boolean;
  readonly port: number;
  readonly logLevel: z.infer<typeof envSchema>["LOG_LEVEL"];
  readonly trustProxy: number;
  readonly httpsEnforced: boolean;
  readonly runMigrationsOnBoot: boolean;
  readonly databaseUrl: string;
  readonly dbPoolMin: number;
  readonly dbPoolMax: number;
  readonly frontendUrl: string;
  readonly authBaseUrl: string;
  readonly allowedOrigins: readonly string[];
  readonly cookieDomain: string | undefined;
  readonly cookieSecure: boolean;
  readonly sessionExpiryDays: number;
  readonly sessionIdleHours: number;
  readonly maxActiveSessions: number;
  readonly sessionSecret: string | undefined;
  readonly mfaEncryptionKeys: readonly EncryptionKeyEntry[];
  readonly argonMemoryKib: number;
  readonly argonTimeCost: number;
  readonly argonParallelism: number;
  readonly argonHashLength: number;
  readonly rateLimiterBackend: "memory" | "redis";
  readonly redisUrl: string;
  readonly rateLimits: Record<RateLimitName, RateLimitSpec>;
  readonly lockDurationMin: number;
  readonly mfaMaxFailedAttempts: number;
  readonly serviceApiKeys: readonly string[];
  readonly breachedPasswordCheckerMode: "local" | "hibp";
  readonly webDistDir: string | undefined;
  readonly jwtPrivateKey: string | undefined;
  readonly jwtIssuer: string;
  readonly jwtAudience: string;
  readonly jwtKid: string | undefined;
  readonly jwtAccessTtlSeconds: number;
  readonly emailProvider: "console" | "smtp";
  readonly emailFrom: string;
  readonly smtpUrl: string | undefined;
  readonly emailRetryMax: number;
  readonly emailRetryBackoffMs: number;
  readonly retentionDays: number;
}

function parseKeyList(raw: string): EncryptionKeyEntry[] {
  const entries = raw
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .map((part) => {
      const match = /^v(\d+):(.+)$/.exec(part);
      if (!match) {
        throw new ConfigError(`MFA_ENCRYPTION_KEYS entry "${part}" must look like v2:base64...`);
      }
      const key = match[2]!;
      const decoded = Buffer.from(key, "base64");
      if (decoded.toString("base64") !== key) {
        throw new ConfigError(`MFA_ENCRYPTION_KEYS entry "${part}" is not valid base64`);
      }
      if (decoded.length !== 32) {
        throw new ConfigError(
          `MFA_ENCRYPTION_KEYS entry "${part}" must decode to exactly 32 bytes (AES-256)`,
        );
      }
      return { version: Number(match[1]!), key };
    });
  const versions = entries.map((e) => e.version);
  if (new Set(versions).size !== versions.length) {
    throw new ConfigError("MFA_ENCRYPTION_KEYS contains duplicate versions.");
  }
  return entries;
}

function requireProdSecrets(parsed: z.infer<typeof envSchema>): void {
  if (parsed.NODE_ENV !== "production") return;
  const failures: string[] = [];
  if (parsed.COOKIE_SECURE !== true) failures.push("COOKIE_SECURE=true");
  if (parsed.HTTPS_ENFORCED !== true) failures.push("HTTPS_ENFORCED=true");
  if (parsed.EMAIL_PROVIDER !== "smtp") failures.push("EMAIL_PROVIDER=smtp");
  if (parsed.RATE_LIMITER_BACKEND !== "redis") failures.push("RATE_LIMITER_BACKEND=redis");
  const serviceKeyList = (parsed.SERVICE_API_KEYS ?? "")
    .split(",")
    .map((k) => k.trim())
    .filter((k) => k.length > 0);
  if (parsed.NODE_ENV === "production") {
    if (serviceKeyList.length === 0) {
      failures.push("SERVICE_API_KEYS (comma-separated, min 16 chars each)");
    } else if (serviceKeyList.some((k) => k.length < 16)) {
      failures.push("SERVICE_API_KEYS entries (min 16 chars each)");
    }
  }
  if (parsed.JWT_PRIVATE_KEY === undefined || parsed.JWT_PRIVATE_KEY.length < 16) {
    failures.push("JWT_PRIVATE_KEY (RS256 PEM)");
  }
  if (parsed.JWT_KID === undefined || parsed.JWT_KID.length === 0) {
    failures.push("JWT_KID");
  }
  if (failures.length > 0) {
    throw new ConfigError(
      `Production configuration is insecure. Set: ${failures.join(", ")}. Refusing to start.`,
    );
  }
}

function requireProdHttps(parsed: z.infer<typeof envSchema>): void {
  if (parsed.NODE_ENV !== "production") return;
  const failures: string[] = [];
  const check = (label: string, value: string) => {
    try {
      if (new URL(value).protocol !== "https:") failures.push(label);
    } catch {
      failures.push(`${label} (not a valid URL)`);
    }
  };
  check("FRONTEND_URL", parsed.FRONTEND_URL);
  check("AUTH_BASE_URL", parsed.AUTH_BASE_URL);
  const origins = parsed.ALLOWED_ORIGINS
    ? parsed.ALLOWED_ORIGINS.split(",").map((s) => s.trim()).filter(Boolean)
    : [];
  origins.forEach((origin) => check(`ALLOWED_ORIGINS entry "${origin}"`, origin));
  if (failures.length > 0) {
    throw new ConfigError(
      `Production environment requires HTTPS URLs. Fix: ${failures.join(", ")}. Refusing to start.`,
    );
  }
}

function parseAllowedOrigins(parsed: z.infer<typeof envSchema>): string[] {
  const entries = parsed.ALLOWED_ORIGINS
    ? parsed.ALLOWED_ORIGINS.split(",").map((s) => s.trim()).filter(Boolean)
    : [parsed.FRONTEND_URL, parsed.AUTH_BASE_URL];
  const invalid = entries.filter((origin) => {
    try {
      new URL(origin);
      return false;
    } catch {
      return true;
    }
  });
  if (invalid.length > 0) {
    throw new ConfigError(
      `Invalid configuration: ALLOWED_ORIGINS entries must be valid URLs: ${invalid.join(", ")}`,
    );
  }
  // Canonicalize to bare origins so Origin-header comparison can't miss on case,
  // trailing path, or explicit default ports; URL drops default ports itself.
  const origins: string[] = [];
  for (const entry of entries) {
    const u = new URL(entry);
    const canonical = `${u.protocol}//${u.host.toLowerCase()}`;
    if (!origins.includes(canonical)) {
      origins.push(canonical);
    }
  }
  return origins;
}

export function loadConfig(env: NodeJS.ProcessEnv): Config {
  const result = envSchema.safeParse(env);
  if (!result.success) {
    const first = result.error.issues[0];
    const where = first?.path.join(".") ?? "unknown";
    throw new ConfigError(`Invalid configuration for "${where}": ${first?.message ?? "unknown error"}`);
  }
  const parsed = result.data;
  if (parsed.EMAIL_PROVIDER === "smtp" && !parsed.SMTP_URL) {
    throw new ConfigError('EMAIL_PROVIDER=smtp requires SMTP_URL (e.g. smtps://user:pass@smtp.example.com:465)');
  }
  requireProdSecrets(parsed);
  requireProdHttps(parsed);

  const mfaEncryptionKeys = parseKeyList(parsed.MFA_ENCRYPTION_KEYS);
  const allowedOrigins = parseAllowedOrigins(parsed);
  const serviceApiKeys = Object.freeze(
    (parsed.SERVICE_API_KEYS ?? "")
      .split(",")
      .map((k) => k.trim())
      .filter((k) => k.length > 0),
  );

  let rateLimits: Record<RateLimitName, RateLimitSpec>;
  try {
    rateLimits = parseRateLimits(parsed.RATE_LIMITS_JSON);
  } catch (err) {
    throw new ConfigError(err instanceof Error ? err.message : "Invalid RATE_LIMITS_JSON");
  }

  const config: Config = {
    nodeEnv: parsed.NODE_ENV,
    isProduction: parsed.NODE_ENV === "production",
    port: parsed.PORT,
    logLevel: parsed.LOG_LEVEL,
    trustProxy: parsed.TRUST_PROXY,
    httpsEnforced: parsed.HTTPS_ENFORCED,
    runMigrationsOnBoot: parsed.RUN_MIGRATIONS_ON_BOOT,
    databaseUrl: parsed.DATABASE_URL,
    dbPoolMin: parsed.DB_POOL_MIN,
    dbPoolMax: parsed.DB_POOL_MAX,
    frontendUrl: parsed.FRONTEND_URL,
    authBaseUrl: parsed.AUTH_BASE_URL,
    allowedOrigins: Object.freeze(allowedOrigins),
    cookieDomain: parsed.COOKIE_DOMAIN,
    cookieSecure: parsed.COOKIE_SECURE,
    sessionExpiryDays: parsed.SESSION_EXPIRY_DAYS,
    sessionIdleHours: parsed.SESSION_IDLE_HOURS,
    maxActiveSessions: parsed.MAX_ACTIVE_SESSIONS,
    sessionSecret: parsed.SESSION_SECRET,
    mfaEncryptionKeys: Object.freeze(mfaEncryptionKeys),
    argonMemoryKib: parsed.ARGON_MEMORY_KIB,
    argonTimeCost: parsed.ARGON_TIME_COST,
    argonParallelism: parsed.ARGON_PARALLELISM,
    argonHashLength: parsed.ARGON_HASH_LENGTH,
    rateLimiterBackend: parsed.RATE_LIMITER_BACKEND,
    redisUrl: parsed.REDIS_URL,
    rateLimits: Object.freeze(rateLimits),
    lockDurationMin: parsed.LOCK_DURATION_MIN,
    mfaMaxFailedAttempts: parsed.MFA_MAX_FAILED_ATTEMPTS,
    serviceApiKeys: Object.freeze(serviceApiKeys),
    // D1: HIBP is the production default; explicit override wins (local keeps tests hermetic).
    breachedPasswordCheckerMode:
      parsed.BREACHED_PASSWORD_CHECKER ??
      (parsed.NODE_ENV === "production" ? "hibp" : "local"),
    webDistDir: parsed.WEB_DIST_DIR,
    jwtPrivateKey: parsed.JWT_PRIVATE_KEY,
    jwtIssuer: parsed.JWT_ISSUER ?? parsed.AUTH_BASE_URL,
    jwtAudience: parsed.JWT_AUDIENCE ?? parsed.AUTH_BASE_URL,
    jwtKid: parsed.JWT_KID,
    jwtAccessTtlSeconds: parsed.JWT_ACCESS_TTL_SECONDS,
    emailProvider: parsed.EMAIL_PROVIDER,
    emailFrom: parsed.EMAIL_FROM,
    smtpUrl: parsed.SMTP_URL,
    emailRetryMax: parsed.EMAIL_RETRY_MAX,
    emailRetryBackoffMs: parsed.EMAIL_RETRY_BACKOFF_MS,
    retentionDays: parsed.RETENTION_DAYS,
  };
  return Object.freeze(config);
}
