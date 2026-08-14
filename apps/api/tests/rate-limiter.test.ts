import Redis from "ioredis";
import { describe, expect, it } from "vitest";
import { InMemoryRateLimiter } from "../src/infrastructure/ratelimit/memory-rate-limiter.js";
import { RedisRateLimiter } from "../src/infrastructure/ratelimit/redis-rate-limiter.js";
import { runRateLimiterSuite } from "./rate-limiter.suite.js";
import { probeRedis, TEST_REDIS_URL } from "./helpers/redis.js";

const redisAvailable = await probeRedis();

runRateLimiterSuite("memory", async () => {
  const limiter = new InMemoryRateLimiter();
  return { limiter, dispose: () => limiter.dispose() };
});

describe("rate limiter (redis fail-closed)", () => {
  it("denies requests when redis errors instead of failing open", async () => {
    const client = {
      incr: async () => {
        throw new Error("connection refused");
      },
      pexpire: async () => 1,
      disconnect: () => undefined,
    } as unknown as Redis;
    const limiter = new RedisRateLimiter(client, { warn: () => undefined });
    const result = await limiter.check("k-failclosed", 3, 60_000);
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
    expect(result.retryAfterMs).toBe(60_000);
  });
});

describe("in-memory limiter sweep", () => {
  it("evicts entries whose window is older than STALE_WINDOW_MS", async () => {
    let now = 0;
    const limiter = new InMemoryRateLimiter({ now: () => now });
    await limiter.check("k-a", 3, 3_600_000);
    await limiter.check("k-b", 3, 3_600_000);
    expect(limiter.size).toBe(2);
    now += 3_600_000 + 61_000;
    await limiter.check("k-c", 3, 3_600_000);
    expect(limiter.size).toBe(1);
    await limiter.dispose();
  });

  it("keeps live entries when a sweep runs", async () => {
    let now = 0;
    const limiter = new InMemoryRateLimiter({ now: () => now });
    await limiter.check("k-a", 3, 3_600_000);
    now += 60_000;
    await limiter.check("k-b", 3, 3_600_000);
    expect(limiter.size).toBe(2);
    await limiter.dispose();
  });
});

if (redisAvailable) {
  runRateLimiterSuite("redis", async () => {
    const client = new Redis(TEST_REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1 });
    await client.connect();
    const limiter = new RedisRateLimiter(client);
    return { limiter, dispose: () => limiter.dispose() };
  });
} else {
  console.warn("redis unavailable — skipping redis rate-limiter tests");
  describe.skip("rate limiter (redis)", () => {});
}
