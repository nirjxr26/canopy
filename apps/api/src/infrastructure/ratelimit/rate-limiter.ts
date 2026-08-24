export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  retryAfterMs: number;
}

export interface RateLimiter {
  readonly backend: "memory" | "redis";
  check(key: string, limit: number, windowMs: number): Promise<RateLimitResult>;
  dispose(): Promise<void>;
  /** Optional liveness probe for /healthz (§11#5 pre-multi-instance requirement). */
  ping?(): Promise<boolean>;
}

export function currentWindowStart(nowMs: number, windowMs: number): number {
  return Math.floor(nowMs / windowMs) * windowMs;
}
