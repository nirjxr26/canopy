import { currentWindowStart, type RateLimiter, type RateLimitResult } from "./rate-limiter.js";

interface WindowEntry {
  windowStart: number;
  count: number;
  lastSeen: number;
  windowMs: number;
}

export const MAX_ENTRIES = 10_000;
// ponytail: sweep at most once a minute regardless of map size
const SWEEP_THROTTLE_MS = 60_000;

export class InMemoryRateLimiter implements RateLimiter {
  readonly backend = "memory" as const;
  private readonly windows = new Map<string, WindowEntry>();
  private lastSweepAt: number;
  private readonly now: () => number;

  constructor(opts?: { now?: () => number }) {
    this.now = opts?.now ?? Date.now;
    this.lastSweepAt = this.now();
  }

  get size(): number {
    return this.windows.size;
  }

  async check(key: string, limit: number, windowMs: number): Promise<RateLimitResult> {
    const now = this.now();
    const windowStart = currentWindowStart(now, windowMs);
    this.sweepIfNeeded(now);

    const entry = this.windows.get(key);
    if (entry?.windowStart !== windowStart) {
      if (entry === undefined && this.windows.size >= MAX_ENTRIES) {
        this.evictOldest(1);
      }
      this.windows.set(key, { windowStart, count: 1, lastSeen: now, windowMs });
      return {
        allowed: limit >= 1,
        limit,
        remaining: Math.max(0, limit - 1),
        retryAfterMs: windowStart + windowMs - now,
      };
    }

    const count = entry.count + 1;
    entry.count = count;
    entry.lastSeen = now;
    return {
      allowed: count <= limit,
      limit,
      remaining: Math.max(0, limit - count),
      retryAfterMs: windowStart + windowMs - now,
    };
  }

  async dispose(): Promise<void> {
    this.windows.clear();
  }

  private sweepIfNeeded(now: number): void {
    if (this.windows.size < MAX_ENTRIES && now - this.lastSweepAt < SWEEP_THROTTLE_MS) {
      return;
    }
    this.lastSweepAt = now;
    for (const [key, entry] of this.windows) {
      if (now - entry.lastSeen > entry.windowMs) {
        this.windows.delete(key);
      }
    }
    if (this.windows.size > MAX_ENTRIES) {
      this.evictOldest(this.windows.size - MAX_ENTRIES);
    }
  }

  private evictOldest(count: number): void {
    for (let i = 0; i < count; i++) {
      let oldestKey: string | undefined;
      let oldestSeen = Number.MAX_SAFE_INTEGER;
      for (const [key, entry] of this.windows) {
        if (entry.lastSeen < oldestSeen) {
          oldestSeen = entry.lastSeen;
          oldestKey = key;
        }
      }
      if (oldestKey !== undefined) {
        this.windows.delete(oldestKey);
      }
    }
  }
}
