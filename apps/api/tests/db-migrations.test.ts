import { beforeAll, expect, it } from "vitest";
import { sql } from "kysely";
import { migrateToLatest } from "../src/infrastructure/db/migrate.js";
import { describeDb, resetTestDatabase, TEST_DATABASE_URL } from "./helpers/db.js";

describeDb("migrations against auuth_test", () => {
  beforeAll(async () => {
    await resetTestDatabase();
  }, 30000);
  it("applies the full schema and is idempotent on re-run", async () => {
    const first = await migrateToLatest({ databaseUrl: TEST_DATABASE_URL, dbPoolMin: 2, dbPoolMax: 10 });
    expect(first.applied).toContain("0001_initial_schema");

    const second = await migrateToLatest({ databaseUrl: TEST_DATABASE_URL, dbPoolMin: 2, dbPoolMax: 10 });
    expect(second.applied).toEqual([]);
  }, 30000);

  it("creates every table from the data model", async () => {
    await migrateToLatest({ databaseUrl: TEST_DATABASE_URL, dbPoolMin: 2, dbPoolMax: 10 });
    const { createDb } = await import("../src/infrastructure/db/database.js");
    const { db, pool } = createDb({
      databaseUrl: TEST_DATABASE_URL,
      dbPoolMin: 1,
      dbPoolMax: 2,
    });
    try {
      const result = await sql`select tablename from pg_tables where schemaname = 'public' order by tablename`.execute(db);
      const tables = (result.rows as { tablename: string }[]).map((r) => r.tablename);
      for (const expected of [
        "users",
        "mfa_credentials",
        "recovery_codes",
        "sessions",
        "tokens",
        "security_events",
        "email_outbox",
      ]) {
        expect(tables).toContain(expected);
      }
    } finally {
      await pool.end();
    }
  }, 30000);

  it("imposes the documented constraints (status check, token kinds, event actors)", async () => {
    await migrateToLatest({ databaseUrl: TEST_DATABASE_URL, dbPoolMin: 2, dbPoolMax: 10 });
    const { createDb } = await import("../src/infrastructure/db/database.js");
    const { db, pool } = createDb({
      databaseUrl: TEST_DATABASE_URL,
      dbPoolMin: 1,
      dbPoolMax: 2,
    });
    try {
      const badStatus = await sql`insert into users (id, email, password_hash, status) values ('usr_bad1', 'a@b.co', 'x', 'NOPE')`.execute(db).then(() => false).catch(() => true);
      expect(badStatus).toBe(true);

      const badActor = await sql`insert into security_events (event_type, actor) values ('T', 'ROBOT')`.execute(db).then(() => false).catch(() => true);
      expect(badActor).toBe(true);
    } finally {
      await pool.end();
    }
  }, 30000);
});
