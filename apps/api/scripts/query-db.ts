import { readFileSync } from "node:fs";
import dotenv from "dotenv";
import { sql } from "kysely";
import { createDb } from "../src/infrastructure/db/database.js";

dotenv.config();
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  process.stderr.write("DATABASE_URL env var is required\n");
  process.exitCode = 1;
} else {
  const { db, pool } = createDb({ databaseUrl, dbPoolMin: 0, dbPoolMax: 10 });
  try {
    let query = process.argv.slice(2).join(" ").trim();
    if (!query) {
      try {
        query = readFileSync(0, "utf8").trim();
      } catch {
        query = "";
      }
    }
    if (!query) {
      process.stderr.write('usage: echo "SELECT ..." | npm run db -w apps/api --\n');
      process.exitCode = 1;
    } else {
      const { rows } = await db.executeQuery(sql.raw(query).compile(db));
      if (rows.length === 0) {
        process.stdout.write("query returned no rows\n");
      } else {
        console.table(rows);
      }
    }
  } catch (err) {
    process.stderr.write(`query failed: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}
