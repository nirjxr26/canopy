import type { Kysely } from "kysely";
import { sql } from "kysely";
import type { Migration } from "kysely/migration";
import { PENDING_VERIFICATION, USER_STATUSES } from "../../../shared/user-status.js";
import type { Database } from "../database.js";
import { emailOutboxHtml } from "./0002_email_outbox_html.js";
import { addMfaFailedAttempts } from "./0003_add_mfa_failed_attempts.js";
import { addOutboxState } from "./0004_email_outbox_state.js";
import { addMfaEnrollTokenKind } from "./0005_add_mfa_enroll_token_kind.js";
import { outboxClaimIndex } from "./0006_outbox_claim_index.js";
import { retentionIndexes } from "./0007_retention_indexes.js";

const STATUS_LIST = USER_STATUSES.map((s) => `'${s}'`).join(",");

export const initialSchema: Migration = {
  up: async (db: Kysely<Database>) => {
    await sql`
      CREATE TABLE users (
        id                TEXT PRIMARY KEY,
        email             TEXT NOT NULL,
        password_hash     TEXT NOT NULL,
        first_name        TEXT,
        last_name         TEXT,
        status            TEXT NOT NULL DEFAULT ${sql.raw(`'${PENDING_VERIFICATION}'`)}
                          CHECK (status IN (${sql.raw(STATUS_LIST)})),
        email_verified_at TIMESTAMPTZ,
        locked_until      TIMESTAMPTZ,
        last_login_at     TIMESTAMPTZ,
        created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
        deleted_at        TIMESTAMPTZ
      );
      CREATE UNIQUE INDEX users_email_key ON users (email) WHERE deleted_at IS NULL
    `.execute(db);
    await sql`
      CREATE TABLE mfa_credentials (
        id                TEXT PRIMARY KEY,
        user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        method            TEXT NOT NULL,
        secret_encrypted  TEXT NOT NULL,
        key_version       INTEGER NOT NULL DEFAULT 1,
        enabled_at        TIMESTAMPTZ,
        created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (user_id, method)
      )
    `.execute(db);
    await sql`
      CREATE TABLE recovery_codes (
        id         TEXT PRIMARY KEY,
        user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash  TEXT NOT NULL,
        used_at    TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `.execute(db);
    await sql`
      CREATE TABLE sessions (
        id           TEXT PRIMARY KEY,
        user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash   TEXT NOT NULL UNIQUE,
        created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
        expires_at   TIMESTAMPTZ NOT NULL,
        last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        ip_address   INET,
        user_agent   TEXT,
        revoked_at   TIMESTAMPTZ
      );
      CREATE INDEX idx_sessions_user ON sessions (user_id)
    `.execute(db);
    await sql`
      CREATE TABLE tokens (
        id          TEXT PRIMARY KEY,
        user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        kind        TEXT NOT NULL CHECK (kind IN ('EMAIL_VERIFICATION','PASSWORD_RESET','MFA_PENDING')),
        token_hash  TEXT NOT NULL UNIQUE,
        expires_at  TIMESTAMPTZ NOT NULL,
        used_at     TIMESTAMPTZ,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        metadata    JSONB NOT NULL DEFAULT '{}'::jsonb
      )
    `.execute(db);
    await sql`
      CREATE TABLE security_events (
        id             BIGSERIAL PRIMARY KEY,
        event_type     TEXT NOT NULL,
        user_id        TEXT REFERENCES users(id) ON DELETE SET NULL,
        actor          TEXT NOT NULL DEFAULT 'USER' CHECK (actor IN ('USER','SYSTEM')),
        ip_address     INET,
        user_agent     TEXT,
        correlation_id TEXT,
        metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
        occurred_at    TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE INDEX idx_events_user ON security_events (user_id, occurred_at DESC);
      CREATE INDEX idx_events_type ON security_events (event_type, occurred_at DESC);
      CREATE INDEX idx_events_time ON security_events (occurred_at DESC)
    `.execute(db);
    await sql`
      CREATE TABLE email_outbox (
        id              BIGSERIAL PRIMARY KEY,
        recipient       TEXT NOT NULL,
        subject         TEXT NOT NULL,
        body            TEXT NOT NULL,
        token_ref       TEXT,
        attempt_count   INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        sent_at         TIMESTAMPTZ,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
      );
      CREATE INDEX idx_outbox_due ON email_outbox (next_attempt_at) WHERE sent_at IS NULL
    `.execute(db);
  },
  down: async (db: Kysely<Database>) => {
    await sql`
      DROP TABLE IF EXISTS email_outbox;
      DROP TABLE IF EXISTS security_events;
      DROP TABLE IF EXISTS tokens;
      DROP TABLE IF EXISTS sessions;
      DROP TABLE IF EXISTS recovery_codes;
      DROP TABLE IF EXISTS mfa_credentials;
      DROP TABLE IF EXISTS users
    `.execute(db);
  },
};

export const migrations: Record<string, Migration> = {
  "0001_initial_schema": initialSchema,
  "0002_email_outbox_html": emailOutboxHtml,
  "0003_add_mfa_failed_attempts": addMfaFailedAttempts,
  "0004_email_outbox_state": addOutboxState,
  "0005_add_mfa_enroll_token_kind": addMfaEnrollTokenKind,
  "0006_outbox_claim_index": outboxClaimIndex,
  "0007_retention_indexes": retentionIndexes,
};
