import { beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import pg from "pg";
import { Kysely, PostgresDialect } from "kysely";
import { createApp } from "../src/app/app.js";
import { loadConfig } from "../src/infrastructure/config/config.js";
import { createLogger } from "../src/infrastructure/logging/logger.js";
import { createDb } from "../src/infrastructure/db/database.js";
import type { Database } from "../src/infrastructure/db/database.js";
import { describeDb, TEST_DATABASE_URL, TEST_MFA_KEY } from "./helpers/db.js";
import { migrateToLatest } from "../src/infrastructure/db/migrate.js";

function makeTestConfig() {
  return loadConfig({
    NODE_ENV: "test",
    DATABASE_URL: TEST_DATABASE_URL,
    FRONTEND_URL: "http://localhost:5173",
    AUTH_BASE_URL: "http://localhost:3000",
    MFA_ENCRYPTION_KEYS: TEST_MFA_KEY,
  });
}

describe("app basics", () => {
  const config = makeTestConfig();
  const logger = createLogger("silent");

  async function withApp(run: (app: ReturnType<typeof createApp>) => Promise<void>): Promise<void> {
    const { db, pool } = createDb(config);
    try {
      await run(createApp({ config, logger, db }));
    } finally {
      await pool.end();
    }
  }

  it("returns X-Request-Id on every response", async () => {
    await withApp(async (app) => {
      const res = await request(app).get("/healthz").set("X-Request-Id", "my-custom-id-123");
      expect(res.header["x-request-id"]).toBe("my-custom-id-123");
    });
  });

  it("generates a request id when none is supplied", async () => {
    await withApp(async (app) => {
      const res = await request(app).get("/healthz");
      expect(res.header["x-request-id"]).toMatch(/^[\w.-]{8,64}$/);
    });
  });

  it("shapes unknown routes as the documented error envelope", async () => {
    await withApp(async (app) => {
      const res = await request(app).get("/api/v1/nope");
      expect(res.status).toBe(404);
      expect(res.body).toMatchObject({
        error: { code: "NOT_FOUND", message: "Not found" },
      });
      expect(typeof res.body.error.requestId).toBe("string");
    });
  });

  it("maps malformed JSON to a 400 VALIDATION error", async () => {
    await withApp(async (app) => {
      const res = await request(app)
        .post("/api/v1/auth/login")
        .set("Content-Type", "application/json")
        .send("{not json");
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe("VALIDATION");
    });
  });

  it("never leaks stack traces or internals", async () => {
    await withApp(async (app) => {
      const res = await request(app)
        .post("/api/v1/auth/login")
        .set("Content-Type", "application/json")
        .send("{broken");
      const body = JSON.stringify(res.body);
      expect(body).not.toContain("at ");
      expect(body).not.toContain("Error");
    });
  });
});

describeDb("healthz with database", () => {
  beforeAll(async () => {
    await migrateToLatest({ databaseUrl: TEST_DATABASE_URL, dbPoolMin: 2, dbPoolMax: 10 });
  });

  it("reports ok when the db is reachable", async () => {
    const config = makeTestConfig();
    const { db, pool } = createDb(config);
    const app = createApp({ config, logger: createLogger("silent"), db });
    try {
      const res = await request(app).get("/healthz");
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: "ok", db: "up" });
    } finally {
      await pool.end();
    }
  });

  it("reports degraded when the db is unreachable", async () => {
    const config = loadConfig({
      NODE_ENV: "test",
      DATABASE_URL: "postgres://postgres:postgres@localhost:59999/auuth_test",
      FRONTEND_URL: "http://localhost:5173",
      AUTH_BASE_URL: "http://localhost:3000",
      MFA_ENCRYPTION_KEYS: TEST_MFA_KEY,
    });
    const pool = new pg.Pool({
      connectionString: config.databaseUrl,
      connectionTimeoutMillis: 1500,
      max: 1,
    });
    const db = new Kysely<Database>({ dialect: new PostgresDialect({ pool }) });
    const app = createApp({ config, logger: createLogger("silent"), db });
    try {
      const res = await request(app).get("/healthz");
      expect(res.status).toBe(503);
      expect(res.body.status).toBe("degraded");
    } finally {
      await pool.end();
    }
  });
});
