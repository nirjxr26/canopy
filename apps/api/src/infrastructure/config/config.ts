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
      ? z.number({ error: "expected a number" }).int().finite().min(min)
      : z.number({ error: "expected a number" }).int().finite().min(min).max(max),
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
  DATABASE_URL: z.string().min(1),
  DB_POOL_MIN: intFrom(0).default(2),
  DB_POOL_MAX: intFrom(1).default(10),
  FRONTEND_URL: urlString,
  AUTH_BASE_URL: urlString,
  ALLOWED_ORIGINS: z.string().optional(),
  COOKIE_DOMAIN: z.string().optional(),
  COOKIE_SECURE: boolFromString.default(false),
  SESSION_EXPIRY_DAYS: intFrom(1, 90).default(30),
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
  LOCK_ESCALATION_COUNT: intFrom(1).default(5),
  CAPTCHA_CHALLENGER: z.enum(["none"]).default("none"),
  SERVICE_API_KEY: z.string().optional(),
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
  readonly databaseUrl: string;
  readonly dbPoolMin: number;
  readonly dbPoolMax: number;
  readonly frontendUrl: string;
  readonly authBaseUrl: string;
  readonly allowedOrigins: readonly string[];
  readonly cookieDomain: string | undefined;
  readonly cookieSecure: boolean;
  readonly sessionExpiryDays: number;
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
  readonly lockEscalationCount: number;
  readonly captchaChallenger: "none";
  readonly serviceApiKey: string | undefined;
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
      if (Buffer.from(key, "base64").toString("base64") !== key) {
        throw new ConfigError(`MFA_ENCRYPTION_KEYS entry "${part}" is not valid base64`);
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
  if (parsed.SERVICE_API_KEY === undefined || parsed.SERVICE_API_KEY.length < 16) {
    failures.push("SERVICE_API_KEY (min 16 chars)");
  }
  if (parsed.JWT_PRIVATE_KEY === undefined || parsed.JWT_PRIVATE_KEY.length < 16) {
    failures.push("JWT_PRIVATE_KEY (RS256 PEM)");
  }
  if (failures.length > 0) {
    throw new ConfigError(
      `Production configuration is insecure. Set: ${failures.join(", ")}. Refusing to start.`,
    );
  }
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

  const mfaEncryptionKeys = parseKeyList(parsed.MFA_ENCRYPTION_KEYS);
  const allowedOrigins = (
    parsed.ALLOWED_ORIGINS
      ? parsed.ALLOWED_ORIGINS.split(",").map((s) => s.trim()).filter(Boolean)
      : [parsed.FRONTEND_URL, parsed.AUTH_BASE_URL]
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
    databaseUrl: parsed.DATABASE_URL,
    dbPoolMin: parsed.DB_POOL_MIN,
    dbPoolMax: parsed.DB_POOL_MAX,
    frontendUrl: parsed.FRONTEND_URL,
    authBaseUrl: parsed.AUTH_BASE_URL,
    allowedOrigins: Object.freeze(allowedOrigins),
    cookieDomain: parsed.COOKIE_DOMAIN,
    cookieSecure: parsed.COOKIE_SECURE,
    sessionExpiryDays: parsed.SESSION_EXPIRY_DAYS,
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
    lockEscalationCount: parsed.LOCK_ESCALATION_COUNT,
    captchaChallenger: parsed.CAPTCHA_CHALLENGER,
    serviceApiKey: parsed.SERVICE_API_KEY,
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
