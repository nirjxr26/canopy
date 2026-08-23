import type { Kysely } from "kysely";
import { sql } from "kysely";
import type { Migration } from "kysely/migration";
import type { Database } from "../database.js";

// Supports the §6.13 retention sweeps (L-62): expiry lookups on sessions and
// tokens, plus the existing idx_events_time for security_events.
export const retentionIndexes: Migration = {
  up: async (db: Kysely<Database>) => {
    await sql`
      CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);
      CREATE INDEX idx_tokens_kind_expires_at ON tokens (kind, expires_at)
    `.execute(db);
  },
  down: async (db: Kysely<Database>) => {
    await sql`
      DROP INDEX IF EXISTS idx_sessions_expires_at;
      DROP INDEX IF EXISTS idx_tokens_kind_expires_at
    `.execute(db);
  },
};
