import { Redis } from "ioredis";
import { currentWindowStart, type RateLimiter, type RateLimitResult } from "./rate-limiter.js";

const INCR_AND_PEXPIRE_SCRIPT = `
  local n = redis.call('INCR', KEYS[1])
  if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
  return n
`;

export class RedisRateLimiter implements RateLimiter {
  readonly backend = "redis" as const;
  private readonly client: Redis;
  private readonly logger: { warn: (message: string) => void };

  constructor(client: Redis, logger: { warn: (message: string) => void } = console) {
    this.client = client;
    this.logger = logger;
  }

  async check(key: string, limit: number, windowMs: number): Promise<RateLimitResult> {
    const now = Date.now();
    const windowStart = currentWindowStart(now, windowMs);
    const redisKey = `rl:${key}:${windowStart}`;

    try {
      const count = (await this.client.eval(INCR_AND_PEXPIRE_SCRIPT, 1, redisKey, windowMs + 1000)) as number;

      return {
        allowed: count <= limit,
        limit,
        remaining: Math.max(0, limit - count),
        retryAfterMs: windowStart + windowMs - now,
      };
    } catch (err) {
      this.logger.warn(
        `rate limiter: redis unavailable, denying request (${err instanceof Error ? err.message : String(err)})`,
      );
      return { allowed: false, limit, remaining: 0, retryAfterMs: windowMs };
    }
  }

  async dispose(): Promise<void> {
    this.client.disconnect();
  }
}
