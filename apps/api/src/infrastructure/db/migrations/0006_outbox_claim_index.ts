import type { Kysely } from "kysely";
import { sql } from "kysely";
import type { Migration } from "kysely/migration";
import type { Database } from "../database.js";

// The outbox claimer (status-based leasing added in 0004) filters on
// sent_at/next_attempt_at/status; the old idx_outbox_due predates `status`.
export const outboxClaimIndex: Migration = {
  up: async (db: Kysely<Database>) => {
    await sql`
      DROP INDEX IF EXISTS idx_outbox_due;
      CREATE INDEX idx_outbox_claim ON email_outbox (next_attempt_at)
        WHERE sent_at IS NULL AND status <> 'dead'
    `.execute(db);
  },
  down: async (db: Kysely<Database>) => {
    await sql`
      DROP INDEX IF EXISTS idx_outbox_claim;
      CREATE INDEX idx_outbox_due ON email_outbox (next_attempt_at) WHERE sent_at IS NULL
    `.execute(db);
  },
};
