import { Redis } from "ioredis";
import type { Config } from "../config/config.js";
import { InMemoryRateLimiter } from "./memory-rate-limiter.js";
import { RedisRateLimiter } from "./redis-rate-limiter.js";
import type { RateLimiter } from "./rate-limiter.js";

export function createRateLimiter(
  config: Pick<Config, "rateLimiterBackend" | "redisUrl">,
  redisClient?: Redis,
): RateLimiter {
  if (config.rateLimiterBackend === "redis") {
    return new RedisRateLimiter(redisClient ?? new Redis(config.redisUrl, { lazyConnect: true, maxRetriesPerRequest: 1 }));
  }
  return new InMemoryRateLimiter();
}
