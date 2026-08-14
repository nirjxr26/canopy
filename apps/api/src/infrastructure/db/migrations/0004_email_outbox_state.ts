import type { Kysely } from "kysely";
import { sql } from "kysely";
import type { Migration } from "kysely/migration";
import type { Database } from "../database.js";

export const addOutboxState: Migration = {
  up: async (db: Kysely<Database>) => {
    await sql`
      ALTER TABLE email_outbox
        ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending', 'processing', 'sent', 'dead')),
        ADD COLUMN locked_until TIMESTAMPTZ,
        ADD COLUMN worker_id TEXT,
        ADD COLUMN message_id TEXT
    `.execute(db);
    await sql`UPDATE email_outbox SET status = 'sent' WHERE sent_at IS NOT NULL`.execute(db);
  },
  down: async (db: Kysely<Database>) => {
    await sql`
      ALTER TABLE email_outbox
        DROP COLUMN IF EXISTS status,
        DROP COLUMN IF EXISTS locked_until,
        DROP COLUMN IF EXISTS worker_id,
        DROP COLUMN IF EXISTS message_id
    `.execute(db);
  },
};