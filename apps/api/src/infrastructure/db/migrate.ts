import { Migrator } from "kysely/migration";
import { configFromEnv } from "../config/env.js";
import type { Config } from "../config/config.js";
import { createDb } from "./database.js";
import { migrations } from "./migrations/0001_initial_schema.js";

export async function migrateToLatest(
  config: Pick<Config, "databaseUrl" | "dbPoolMin" | "dbPoolMax">,
): Promise<{ applied: string[] }> {
  // statement_timeout=0 disables the pool's 5s cap — DDL can legitimately run longer.
  const { db, pool } = createDb(config, undefined, { statementTimeoutMs: 0 });
  try {
    const migrator = new Migrator({
      db,
      provider: { getMigrations: async () => migrations },
    });
    const result = await migrator.migrateToLatest();
    const applied =
      result.results?.filter((r) => r.status === "Success").map((r) => r.migrationName) ?? [];
    if (result.error) {
      throw result.error;
    }
    return { applied };
  } finally {
    await pool.end();
  }
}

async function main(): Promise<void> {
  const config = configFromEnv();
  const { applied } = await migrateToLatest(config);
  if (applied.length === 0) {
    process.stdout.write("migrations: nothing to apply (schema is up to date)\n");
  } else {
    process.stdout.write(`migrations: applied ${applied.join(", ")}\n`);
  }
}

if (process.argv[1]?.endsWith("migrate.ts") || process.argv[1]?.endsWith("migrate.js")) {
  try {
    await main();
  } catch (err) {
    process.stderr.write(`migrations failed: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  }
}
