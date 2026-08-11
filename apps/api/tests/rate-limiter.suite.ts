import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { RateLimiter } from "../src/infrastructure/ratelimit/rate-limiter.js";

export function runRateLimiterSuite(
  backendName: string,
  makeLimiter: () => Promise<{ limiter: RateLimiter; dispose: () => Promise<void> }>,
): void {
  describe(`rate limiter (${backendName})`, () => {
    it("allows requests under the limit", async () => {
      const { limiter, dispose } = await makeLimiter();
      try {
        const key = `k-${randomUUID()}`;
        const first = await limiter.check(key, 3, 60_000);
        expect(first.allowed).toBe(true);
        expect(first.remaining).toBe(2);
        const second = await limiter.check(key, 3, 60_000);
        expect(second.allowed).toBe(true);
        expect(second.remaining).toBe(1);
      } finally {
        await dispose();
      }
    });

    it("denies once the limit is exceeded", async () => {
      const { limiter, dispose } = await makeLimiter();
      try {
        const key = `k-${randomUUID()}`;
        for (let i = 0; i < 3; i++) {
          expect((await limiter.check(key, 3, 60_000)).allowed).toBe(true);
        }
        const denied = await limiter.check(key, 3, 60_000);
        expect(denied.allowed).toBe(false);
        expect(denied.remaining).toBe(0);
        expect(denied.retryAfterMs).toBeGreaterThan(0);
        expect(denied.retryAfterMs).toBeLessThanOrEqual(60_000);
      } finally {
        await dispose();
      }
    });

    it("resets when the fixed window elapses", async () => {
      const { limiter, dispose } = await makeLimiter();
      try {
        const key = `k-${randomUUID()}`;
        const windowMs = 200;
        expect((await limiter.check(key, 1, windowMs)).allowed).toBe(true);
        expect((await limiter.check(key, 1, windowMs)).allowed).toBe(false);
        await new Promise((resolve) => setTimeout(resolve, windowMs + 50));
        expect((await limiter.check(key, 1, windowMs)).allowed).toBe(true);
      } finally {
        await dispose();
      }
    });

    it("treats different keys independently", async () => {
      const { limiter, dispose } = await makeLimiter();
      try {
        const keyA = `k-${randomUUID()}`;
        const keyB = `k-${randomUUID()}`;
        for (let i = 0; i < 5; i++) {
          await limiter.check(keyA, 2, 60_000);
        }
        expect((await limiter.check(keyA, 2, 60_000)).allowed).toBe(false);
        expect((await limiter.check(keyB, 2, 60_000)).allowed).toBe(true);
      } finally {
        await dispose();
      }
    });
  });
}
