import { currentWindowStart, type RateLimiter, type RateLimitResult } from "./rate-limiter.js";

interface WindowEntry {
  windowStart: number;
  count: number;
}

const MAX_ENTRIES_BEFORE_SWEEP = 10_000;
// ponytail: sweep at most once a minute regardless of map size
const SWEEP_THROTTLE_MS = 60_000;
// ponytail: entries older than 1h are stale — the 1h cutoff sits at the max
// configured window (3_600_000ms, see DEFAULT_RATE_LIMITS) so no live window
// is ever evicted
const STALE_WINDOW_MS = 3_600_000;

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
    if (entry === undefined || entry.windowStart !== windowStart) {
      this.windows.set(key, { windowStart, count: 1 });
      return {
        allowed: limit >= 1,
        limit,
        remaining: Math.max(0, limit - 1),
        retryAfterMs: windowStart + windowMs - now,
      };
    }

    const count = entry.count + 1;
    entry.count = count;
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
    if (this.windows.size < MAX_ENTRIES_BEFORE_SWEEP && now - this.lastSweepAt < SWEEP_THROTTLE_MS) {
      return;
    }
    this.lastSweepAt = now;
    const cutoff = now - STALE_WINDOW_MS;
    for (const [key, entry] of this.windows) {
      if (entry.windowStart < cutoff) {
        this.windows.delete(key);
      }
    }
  }
}
