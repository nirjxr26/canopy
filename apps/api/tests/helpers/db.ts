import pg from "pg";
import { describe } from "vitest";

const BASE_TEST_URL =
  process.env.TEST_DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/auuth_test";

// M-41: every vitest worker gets its OWN physical database so integration
// files can run in parallel without nuking each other's schema.
const TEST_URL_PATTERN = /^(postgres(?:ql)?:\/\/[^/?]+\/)([^/?]+)(\?.*)?$/;
const urlMatch = TEST_URL_PATTERN.exec(BASE_TEST_URL);
const adminBase = urlMatch?.[1];
const baseDbName = urlMatch?.[2];
const urlSearch = urlMatch?.[3] ?? "";
if (!adminBase || !baseDbName?.endsWith("_test")) {
  throw new Error(`TEST_DATABASE_URL must point at a *_test database, got "${BASE_TEST_URL}"`);
}
const workerId = process.env.VITEST_POOL_ID ?? process.env.VITEST_WORKER_ID ?? "0";
export const TEST_DATABASE_URL = `${adminBase}${baseDbName}_w${workerId}${urlSearch}`;

export const TEST_MFA_KEY = "v1:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

// VITEST_STRICT=1 (CI): a missing database/Redis FAILS the run instead of
// silently skipping whole suites — "green" must mean "actually ran".
const STRICT = process.env.VITEST_STRICT === "1";

async function ensureWorkerDatabase(): Promise<void> {
  const adminUrl = `${adminBase}postgres`;
  const dbNameMatch = /\/\/[^/]+\/([^?]+)/.exec(TEST_DATABASE_URL);
  const dbName = dbNameMatch?.[1];
  if (!dbName) {
    throw new Error("cannot derive worker database name from TEST_DATABASE_URL");
  }
  const pool = new pg.Pool({ connectionString: adminUrl, connectionTimeoutMillis: 3000, max: 1 });
  try {
    const exists = await pool.query("select 1 from pg_database where datname = $1", [dbName]);
    if (exists.rowCount === 0) {
      await pool.query(`CREATE DATABASE "${dbName}"`);
    }
  } finally {
    await pool.end().catch(() => undefined);
  }
}

await ensureWorkerDatabase();

export async function probeDatabase(url: string = TEST_DATABASE_URL): Promise<boolean> {
  // Retry briefly — right after CREATE DATABASE, first connections can race.
  for (let attempt = 0; attempt < 5; attempt++) {
    const pool = new pg.Pool({ connectionString: url, connectionTimeoutMillis: 1500, max: 1 });
    try {
      const result = await Promise.race([
        pool.query("select 1 as ok"),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error("db probe timeout")), 2000),
        ),
      ]);
      if (result.rows[0]?.ok === 1) return true;
    } catch {
      // retry
    } finally {
      await pool.end().catch(() => undefined);
    }
    await new Promise((r) => setTimeout(r, 250 * (attempt + 1)));
  }
  return false;
}

export async function resetTestDatabase(url: string = TEST_DATABASE_URL): Promise<void> {
  const dbName = new URL(url).pathname.replace(/^\//, "");
  // Base name and per-worker variants (auuth_test, auuth_test_w3) are allowed.
  if (!/^.*_test(_w\d+)?$/.test(dbName)) {
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

const describeDbOrThrow = ((..._args: Parameters<typeof describe>): ReturnType<typeof describe> => {
  throw new Error(
    "Postgres unavailable but VITEST_STRICT=1 — refusing to silently skip DB-dependent suites",
  );
}) as unknown as typeof describe;

let describeFn: typeof describe = describe;
if (!dbAvailable) {
  if (STRICT) {
    describeFn = describeDbOrThrow;
  } else {
    // Local convenience only — CI runs with VITEST_STRICT=1 (S1607 handled above).
    describeFn = describe.skip as unknown as typeof describe;
  }
}

export const describeDb = describeFn;
