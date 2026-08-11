import type { NextFunction, Request, Response } from "express";
import { AppError, ERROR_CODES } from "../../shared/app-error.js";
import type { RateLimitSpec } from "../../infrastructure/config/rate-limits.js";
import type { RateLimiter } from "../../infrastructure/ratelimit/rate-limiter.js";

export type RateLimitKeyFn = (req: Request) => string;

export function createRateLimit(
  limiter: RateLimiter,
  spec: RateLimitSpec,
  keyFn: RateLimitKeyFn,
) {
  return function rateLimit(req: Request, res: Response, next: NextFunction): void {
    void (async () => {
      const result = await limiter.check(keyFn(req), spec.limit, spec.windowMs);
      res.setHeader("X-RateLimit-Limit", String(spec.limit));
      res.setHeader("X-RateLimit-Remaining", String(result.remaining));
      if (!result.allowed) {
        next(new AppError(ERROR_CODES.RATE_LIMITED, "Too many requests", result.retryAfterMs));
        return;
      }
      next();
    })().catch(next);
  };
}

export function ipKeyFn(req: Request): string {
  return req.ip ?? "unknown";
}
