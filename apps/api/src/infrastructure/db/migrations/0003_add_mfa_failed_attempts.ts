import type { Kysely } from "kysely";
import { sql } from "kysely";
import type { Migration } from "kysely/migration";
import type { Database } from "../database.js";

export const addMfaFailedAttempts: Migration = {
  up: async (db: Kysely<Database>) => {
    await sql`
      ALTER TABLE tokens ADD COLUMN mfa_failed_attempts INTEGER NOT NULL DEFAULT 0
    `.execute(db);
    await sql`
      UPDATE tokens
      SET mfa_failed_attempts = GREATEST(COALESCE((metadata->>'mfaFailedAttempts')::int, 0), 0)
      WHERE kind = 'MFA_PENDING'
        AND metadata ? 'mfaFailedAttempts'
        AND (metadata->>'mfaFailedAttempts') ~ '^[0-9]+$'
    `.execute(db);
  },
  down: async (db: Kysely<Database>) => {
    await sql`ALTER TABLE tokens DROP COLUMN IF EXISTS mfa_failed_attempts`.execute(db);
  },
};