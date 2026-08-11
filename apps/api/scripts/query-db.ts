import { readFileSync } from "node:fs";
import dotenv from "dotenv";
import { createDb } from "../src/infrastructure/db/database.js";

async function main(): Promise<void> {
  dotenv.config();
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    process.stderr.write("DATABASE_URL env var is required\n");
    process.exitCode = 1;
    return;
  }
  const { db, pool } = createDb({ databaseUrl, dbPoolMin: 0, dbPoolMax: 10 });
  try {
    let sql = process.argv.slice(2).join(" ").trim();
    if (!sql) {
      try {
        sql = readFileSync(0, "utf8").trim();
      } catch {
        sql = "";
      }
    }
    if (!sql) {
      process.stderr.write('usage: echo "SELECT ..." | npm run db -w apps/api --\n');
      process.exitCode = 1;
      return;
    }
    const { rows } = await db.executeQuery({ sql, parameters: [] });
    if (rows.length === 0) {
      process.stdout.write("query returned no rows\n");
    } else {
      console.table(rows);
    }
  } catch (err) {
    process.stderr.write(`query failed: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

main();
