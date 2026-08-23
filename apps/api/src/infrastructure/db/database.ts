import pg from "pg";
import { Kysely, PostgresDialect, sql, type ColumnType, type Generated, type Transaction } from "kysely";
import type { UserStatus } from "../../shared/user-status.js";
import type { Config } from "../config/config.js";

export type UserStatusValue = UserStatus;

export interface UsersTable {
  id: string;
  email: string;
  password_hash: string;
  first_name: string | null;
  last_name: string | null;
  status: UserStatusValue;
  email_verified_at: Date | null;
  locked_until: Date | null;
  last_login_at: Date | null;
  created_at: ColumnType<Date, never, never>;
  updated_at: ColumnType<Date, never, Date>;
  deleted_at: Date | null;
}

export interface MfaCredentialsTable {
  id: string;
  user_id: string;
  method: string;
  secret_encrypted: string;
  key_version: number;
  enabled_at: Date | null;
  created_at: ColumnType<Date, never, never>;
}

export interface RecoveryCodesTable {
  id: string;
  user_id: string;
  code_hash: string;
  used_at: Date | null;
  created_at: ColumnType<Date, never, never>;
}

export interface SessionsTable {
  id: string;
  user_id: string;
  token_hash: string;
  created_at: ColumnType<Date, never, never>;
  expires_at: Date;
  last_used_at: ColumnType<Date, never, Date>;
  ip_address: string | null;
  user_agent: string | null;
  revoked_at: Date | null;
}

export interface TokensTable {
  id: string;
  user_id: string;
  kind: string;
  token_hash: string;
  expires_at: Date;
  used_at: Date | null;
  created_at: ColumnType<Date, never, never>;
  mfa_failed_attempts: Generated<number>;
  metadata: ColumnType<Record<string, unknown>, Record<string, unknown>, Record<string, unknown>>;
}

export interface SecurityEventsTable {
  id: ColumnType<number, never, never>;
  event_type: string;
  user_id: string | null;
  actor: string;
  ip_address: string | null;
  user_agent: string | null;
  correlation_id: string | null;
  metadata: ColumnType<Record<string, unknown>, Record<string, unknown>, never>;
  occurred_at: ColumnType<Date, never, never>;
}

export interface EmailOutboxTable {
  id: ColumnType<number, never, never>;
  recipient: string;
  subject: string;
  body: string;
  html_body: string | null;
  token_ref: string | null;
  attempt_count: number;
  next_attempt_at: Date;
  sent_at: Date | null;
  created_at: ColumnType<Date, never, never>;
  status: string;
  locked_until: Date | null;
  worker_id: string | null;
  message_id: string;
}

export interface Database {
  users: UsersTable;
  mfa_credentials: MfaCredentialsTable;
  recovery_codes: RecoveryCodesTable;
  sessions: SessionsTable;
  tokens: TokensTable;
  security_events: SecurityEventsTable;
  email_outbox: EmailOutboxTable;
}

export type DbExecutor = Kysely<Database> | Transaction<Database>;

export function createDb(
  config: Pick<Config, "databaseUrl" | "dbPoolMin" | "dbPoolMax">,
  onError: (err: Error) => void = (err) => console.error("idle postgres client error:", err.message),
  opts?: { statementTimeoutMs?: number },
): {
  pool: pg.Pool;
  db: Kysely<Database>;
} {
  const pool = new pg.Pool({
    connectionString: config.databaseUrl,
    min: config.dbPoolMin,
    max: config.dbPoolMax,
    connectionTimeoutMillis: 5_000,
    statement_timeout: opts?.statementTimeoutMs ?? 5_000,
  });
  // Without this handler an idle-client failure emits an unhandled 'error' event and crashes the process.
  pool.on("error", onError);
  const db = new Kysely<Database>({
    dialect: new PostgresDialect({ pool }),
  });
  return { pool, db };
}

export async function pingDb(db: Kysely<Database>): Promise<boolean> {
  try {
    await sql`select 1 as ok`.execute(db);
    return true;
  } catch {
    return false;
  }
}
