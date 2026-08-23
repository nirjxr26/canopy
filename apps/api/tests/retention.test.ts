import { beforeAll, expect, it } from "vitest";
import { sql } from "kysely";
import { describeDb, resetTestDatabase, TEST_DATABASE_URL, TEST_MFA_KEY } from "./helpers/db.js";
import { migrateToLatest } from "../src/infrastructure/db/migrate.js";
import { loadConfig } from "../src/infrastructure/config/config.js";
import { createDb } from "../src/infrastructure/db/database.js";
import type { Database } from "../src/infrastructure/db/database.js";
import { createRetentionJob } from "../src/infrastructure/jobs/retention.js";

const ORIGIN = "http://localhost:5173";

function makeConfig() {
  return loadConfig({
    NODE_ENV: "test",
    DATABASE_URL: TEST_DATABASE_URL,
    FRONTEND_URL: ORIGIN,
    AUTH_BASE_URL: "http://localhost:3000",
    MFA_ENCRYPTION_KEYS: TEST_MFA_KEY,
    RETENTION_DAYS: "90",
  });
}

async function seedAgedData(db: Kysely<Database>, now: Date): Promise<{ userId: string }> {
  const userId = `usr_retention${Math.floor(Math.random() * 1e6)}`.slice(0, 20);
  await sql`
    insert into users (id, email, password_hash, status)
    values (${userId}, ${`retention-${userId}@example.com`}, 'x', 'ACTIVE')
  `.execute(db);

  const old = new Date(now.getTime() - 200 * 86_400_000);
  const fresh = new Date(now.getTime() - 1 * 86_400_000);
  const future = new Date(now.getTime() + 30 * 86_400_000);

  // Aged session with PII -> anonymized then purged (revoked + old)
  await sql`
    insert into sessions (id, user_id, token_hash, created_at, expires_at, last_used_at, ip_address, user_agent, revoked_at)
    values ('sess_old', ${userId}, 'th-old', ${old.toISOString()}, ${old.toISOString()}, ${old.toISOString()}, '203.0.113.9', 'agent-old', ${old.toISOString()})
  `.execute(db);
  // Fresh session with PII -> anonymized? NO (fresh), stays intact
  await sql`
    insert into sessions (id, user_id, token_hash, created_at, expires_at, last_used_at, ip_address, user_agent)
    values ('sess_fresh', ${userId}, 'th-fresh', ${fresh.toISOString()}, ${future.toISOString()}, ${fresh.toISOString()}, '198.51.100.7', 'agent-fresh')
  `.execute(db);

  // Aged expired token -> purged; fresh token -> untouched
  await sql`
    insert into tokens (id, user_id, kind, token_hash, expires_at)
    values ('tok_old', ${userId}, 'EMAIL_VERIFICATION', 'th-tok-old', ${old.toISOString()})
  `.execute(db);
  await sql`
    insert into tokens (id, user_id, kind, token_hash, expires_at)
    values ('tok_new', ${userId}, 'EMAIL_VERIFICATION', 'th-tok-new', ${future.toISOString()})
  `.execute(db);

  // Aged security event with IP -> anonymized
  await sql`
    insert into security_events (event_type, user_id, ip_address, user_agent, occurred_at)
    values ('LOGIN_SUCCESS', ${userId}, '203.0.113.5', 'ua-old', ${old.toISOString()})
  `.execute(db);

  return { userId };
}

describeDb("retention job (§6.13 / R-29)", () => {
  let pool: import("pg").Pool;
  let db: Kysely<Database>;

  beforeAll(async () => {
    await resetTestDatabase();
    await migrateToLatest({ databaseUrl: TEST_DATABASE_URL, dbPoolMin: 2, dbPoolMax: 10 });
    const config = makeConfig();
    ({ db, pool } = createDb(config));
  });

  it("anonymizes old rows, purges dead tokens/sessions, leaves fresh rows intact", async () => {
    const config = makeConfig();
    const now = new Date();
    const { userId } = await seedAgedData(db, now);
    const job = createRetentionJob(db, { retentionDays: config.retentionDays });

    const stats = await job.runOnce(now);
    expect(stats.anonymizedSessions).toBe(1);
    expect(stats.anonymizedEvents).toBeGreaterThanOrEqual(1);
    expect(stats.purgedTokens).toBeGreaterThanOrEqual(1);
    expect(stats.purgedSessions).toBeGreaterThanOrEqual(1);

    const agedSession = await db
      .selectFrom("sessions")
      .selectAll()
      .where("id", "=", "sess_old")
      .executeTakeFirst();
    // sess_old was purged (old + revoked)
    expect(agedSession).toBeUndefined();

    const freshSession = await db
      .selectFrom("sessions")
      .selectAll()
      .where("id", "=", "sess_fresh")
      .executeTakeFirstOrThrow();
    expect((freshSession as Record<string, unknown>).ip_address).toBe("198.51.100.7");
    expect((freshSession as Record<string, unknown>).user_agent).toBe("agent-fresh");

    const oldToken = await db.selectFrom("tokens").selectAll().where("id", "=", "tok_old").executeTakeFirst();
    expect(oldToken).toBeUndefined();
    const newToken = await db.selectFrom("tokens").selectAll().where("id", "=", "tok_new").executeTakeFirst();
    expect(newToken).toBeDefined();

    const event = await db
      .selectFrom("security_events")
      .selectAll()
      .where("user_id", "=", userId)
      .orderBy("occurred_at", "asc")
      .executeTakeFirstOrThrow();
    expect((event as Record<string, unknown>).ip_address).toBeNull();
    expect((event as Record<string, unknown>).user_agent).toBeNull();
    void userId;
  }, 30000);

  it("is idempotent — a second run changes nothing", async () => {
    const config = makeConfig();
    const job = createRetentionJob(db, { retentionDays: config.retentionDays });
    const stats = await job.runOnce(new Date());
    expect(stats.anonymizedSessions).toBe(0);
    expect(stats.anonymizedEvents).toBe(0);
    expect(stats.purgedTokens).toBe(0);
    expect(stats.purgedSessions).toBe(0);
  }, 30000);
});
