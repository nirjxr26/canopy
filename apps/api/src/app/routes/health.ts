import { Router } from "express";
import type { Kysely } from "kysely";
import type { Database } from "../../infrastructure/db/database.js";
import { pingDb } from "../../infrastructure/db/database.js";

const HEALTH_CACHE_MS = 5_000;

export function createHealthRouter(db: Kysely<Database>): Router {
  const router = Router();
  let cached: { at: number; up: boolean } | null = null;

  router.get("/healthz", async (_req, res) => {
    const now = Date.now();
    // Cache the probe briefly so load balancers hammering /healthz cannot amplify DB load.
    if (cached === null || now - cached.at >= HEALTH_CACHE_MS) {
      const up = await pingDb(db);
      cached = { at: now, up };
    }
    if (cached.up) {
      res.status(200).json({ status: "ok", db: "up" });
    } else {
      res.status(503).json({ status: "degraded", db: "down" });
    }
  });

  return router;
}
