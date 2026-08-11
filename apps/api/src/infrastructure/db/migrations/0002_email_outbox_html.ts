import type { Kysely } from "kysely";
import { sql } from "kysely";
import type { Migration } from "kysely/migration";
import type { Database } from "../database.js";

export const emailOutboxHtml: Migration = {
  up: async (db: Kysely<Database>) => {
    await sql`ALTER TABLE email_outbox ADD COLUMN html_body TEXT`.execute(db);
  },
  down: async (db: Kysely<Database>) => {
    await sql`ALTER TABLE email_outbox DROP COLUMN IF EXISTS html_body`.execute(db);
  },
};
