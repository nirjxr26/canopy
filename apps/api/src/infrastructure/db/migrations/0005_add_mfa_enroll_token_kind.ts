import type { Kysely } from "kysely";
import { sql } from "kysely";
import type { Migration } from "kysely/migration";
import type { Database } from "../database.js";

export const addMfaEnrollTokenKind: Migration = {
  up: async (db: Kysely<Database>) => {
    await sql`
      ALTER TABLE tokens
        DROP CONSTRAINT tokens_kind_check,
        ADD CONSTRAINT tokens_kind_check
          CHECK (kind IN ('EMAIL_VERIFICATION','PASSWORD_RESET','MFA_PENDING','MFA_ENROLL'))
    `.execute(db);
  },
  down: async (db: Kysely<Database>) => {
    await sql`
      ALTER TABLE tokens
        DROP CONSTRAINT tokens_kind_check,
        ADD CONSTRAINT tokens_kind_check
          CHECK (kind IN ('EMAIL_VERIFICATION','PASSWORD_RESET','MFA_PENDING'))
    `.execute(db);
  },
};