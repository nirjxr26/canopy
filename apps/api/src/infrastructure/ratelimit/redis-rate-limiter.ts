import { Redis } from "ioredis";
import { currentWindowStart, type RateLimiter, type RateLimitResult } from "./rate-limiter.js";

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
      const count = await this.client.incr(redisKey);
      if (count === 1) {
        await this.client.pexpire(redisKey, windowMs + 1000);
      }

      return {
        allowed: count <= limit,
        limit,
        remaining: Math.max(0, limit - count),
        retryAfterMs: windowStart + windowMs - now,
      };
    } catch (err) {
      this.logger.warn(
        `rate limiter: redis unavailable, allowing request (${err instanceof Error ? err.message : String(err)})`,
      );
      // ponytail: accept the window-key TTL leak if incr succeeded but pexpire
      // failed — keys are window-scoped so a stale key is never touched again.
      return { allowed: true, limit, remaining: limit, retryAfterMs: 0 };
    }
  }

  async dispose(): Promise<void> {
    this.client.disconnect();
  }
}
