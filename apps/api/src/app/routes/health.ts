import { Router } from "express";
import type { Kysely } from "kysely";
import type { Database } from "../../infrastructure/db/database.js";
import { pingDb } from "../../infrastructure/db/database.js";
import type { RateLimiter } from "../../infrastructure/ratelimit/rate-limiter.js";

const HEALTH_CACHE_MS = 5_000;

export function createHealthRouter(db: Kysely<Database>, limiter?: RateLimiter): Router {
  const router = Router();
  const redisBackend = limiter?.backend === "redis" && typeof limiter.ping === "function";
  let cached: { at: number; dbUp: boolean; redisUp: boolean | null } | null = null;

  router.get("/healthz", async (_req, res) => {
    const now = Date.now();
    // Cache the probe briefly so load balancers hammering /healthz cannot amplify DB load.
    if (cached === null || now - cached.at >= HEALTH_CACHE_MS) {
      const dbUp = await pingDb(db);
      let redisUp: boolean | null = null;
      if (redisBackend && limiter?.ping) {
        redisUp = await limiter.ping();
      }
      cached = { at: now, dbUp, redisUp };
    }

    const body: Record<string, string> = {
      status: cached.dbUp ? "ok" : "degraded",
      db: cached.dbUp ? "up" : "down",
    };
    // §11#5: multi-instance rollouts need the Redis dimension visible.
    if (cached.redisUp !== null) {
      body.redis = cached.redisUp ? "up" : "down";
      if (!cached.redisUp) body.status = "degraded";
    }
    res.status(cached.dbUp ? 200 : 503).json(body);
  });

  return router;
}
