export interface RateLimitSpec {
  limit: number;
  windowMs: number;
}

export const DEFAULT_RATE_LIMITS = {
  loginIp: { limit: 20, windowMs: 60_000 },
  loginFailed: { limit: 5, windowMs: 900_000 },
  loginAccount: { limit: 5, windowMs: 900_000 },
  signup: { limit: 5, windowMs: 3_600_000 },
  forgotPassword: { limit: 5, windowMs: 3_600_000 },
  resetPassword: { limit: 5, windowMs: 3_600_000 },
  resendVerification: { limit: 3, windowMs: 3_600_000 },
  verifyEmail: { limit: 10, windowMs: 3_600_000 },
  changePassword: { limit: 5, windowMs: 900_000 },
  introspect: { limit: 600, windowMs: 60_000 },
  tokens: { limit: 10, windowMs: 60_000 },
  jwks: { limit: 600, windowMs: 60_000 },
  me: { limit: 60, windowMs: 60_000 },
  sessionsList: { limit: 30, windowMs: 60_000 },
  sessionRevoke: { limit: 30, windowMs: 60_000 },
  sessionsAll: { limit: 10, windowMs: 60_000 },
  logout: { limit: 30, windowMs: 60_000 },
  mfaEnroll: { limit: 3, windowMs: 3_600_000 },
  mfaDisable: { limit: 3, windowMs: 3_600_000 },
  mfaVerify: { limit: 10, windowMs: 60_000 },
} as const;

export type RateLimitName = keyof typeof DEFAULT_RATE_LIMITS;

const RATE_LIMITS_JSON_SCHEMA = `{
  "loginIp": { "limit": 20, "windowMs": 60000 }
}`;

export function parseRateLimits(raw: string | undefined): Record<RateLimitName, RateLimitSpec> {
  if (raw === undefined || raw.trim() === "") {
    return { ...DEFAULT_RATE_LIMITS };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(
      `RATE_LIMITS_JSON is not valid JSON. Expected shape: ${RATE_LIMITS_JSON_SCHEMA}`,
    );
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`RATE_LIMITS_JSON must be an object. Expected shape: ${RATE_LIMITS_JSON_SCHEMA}`);
  }
  const result: Record<RateLimitName, RateLimitSpec> = { ...DEFAULT_RATE_LIMITS };
  for (const [name, spec] of Object.entries(parsed as Record<string, unknown>)) {
    if (!(name in result)) {
      throw new Error(`RATE_LIMITS_JSON contains unknown limit "${name}".`);
    }
    if (typeof spec !== "object" || spec === null) {
      throw new Error(`RATE_LIMITS_JSON.${name} must be an object with limit and windowMs.`);
    }
    const { limit, windowMs } = spec as { limit?: unknown; windowMs?: unknown };
    if (
      typeof limit !== "number" ||
      !Number.isInteger(limit) ||
      limit < 1 ||
      typeof windowMs !== "number" ||
      !Number.isInteger(windowMs) ||
      windowMs < 1
    ) {
      throw new Error(`RATE_LIMITS_JSON.${name} needs integer limit >= 1 and windowMs >= 1.`);
    }
    result[name as RateLimitName] = { limit, windowMs };
  }
  return result;
}
