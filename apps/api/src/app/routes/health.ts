import { Router } from "express";
import type { Kysely } from "kysely";
import type { Database } from "../../infrastructure/db/database.js";
import { pingDb } from "../../infrastructure/db/database.js";

export function createHealthRouter(db: Kysely<Database>): Router {
  const router = Router();

  router.get("/healthz", async (_req, res) => {
    const up = await pingDb(db);
    if (up) {
      res.status(200).json({ status: "ok", db: "up" });
    } else {
      res.status(503).json({ status: "degraded", db: "down" });
    }
  });

  return router;
}
