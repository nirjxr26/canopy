import pg from "pg";
import { describe } from "vitest";

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/auuth_test";

export const TEST_MFA_KEY = "v1:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

export async function probeDatabase(url: string = TEST_DATABASE_URL): Promise<boolean> {
  const pool = new pg.Pool({ connectionString: url, connectionTimeoutMillis: 1500, max: 1 });
  try {
    const result = await Promise.race([
      pool.query("select 1 as ok"),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("db probe timeout")), 2000),
      ),
    ]);
    return result.rows[0]?.ok === 1;
  } catch {
    return false;
  } finally {
    await pool.end().catch(() => undefined);
  }
}

export async function resetTestDatabase(url: string = TEST_DATABASE_URL): Promise<void> {
  const dbName = new URL(url).pathname.replace(/^\//, "");
  if (!dbName.endsWith("_test")) {
    throw new Error(`Refusing to reset database "${dbName}": name must end with _test`);
  }
  const pool = new pg.Pool({ connectionString: url, connectionTimeoutMillis: 3000, max: 1 });
  try {
    // Reset search_path so we can drop public without errors
    await pool.query("SET search_path TO pg_catalog, pg_temp");
    await pool.query("DROP SCHEMA IF EXISTS public CASCADE");
    await pool.query("CREATE SCHEMA public");
    await pool.query("SET search_path TO public");
  } finally {
    await pool.end().catch(() => undefined);
  }
}

export const dbAvailable = await probeDatabase();
export const describeDb = dbAvailable ? describe : describe.skip;
