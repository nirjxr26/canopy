import type { Kysely } from "kysely";
import { sql } from "kysely";
import type { Database, DbExecutor } from "../../infrastructure/db/database.js";

export type TokenKind = "EMAIL_VERIFICATION" | "PASSWORD_RESET" | "MFA_PENDING";

export interface NewToken {
  id: string;
  userId: string;
  kind: TokenKind;
  tokenHash: string;
  expiresAt: Date;
  metadata?: Record<string, unknown>;
}

export interface PendingToken {
  id: string;
  userId: string;
  metadata: Record<string, unknown>;
}

export interface TokenRepository {
  insert(token: NewToken): Promise<void>;
  consumeByHash(kind: TokenKind, tokenHash: string, now: Date): Promise<string | null>;
  findByHash(kind: TokenKind, tokenHash: string, now: Date): Promise<PendingToken | null>;
  updateMetadata(id: string, patch: Record<string, unknown>): Promise<boolean>;
  incrementMfaFailures(id: string): Promise<number | null>;
  markUsed(id: string, now: Date): Promise<void>;
  /** Marks every unconsumed token of a kind for a user as used (e.g. renewing verification links). */
  invalidateAll(kind: TokenKind, userId: string): Promise<number>;
}

export function createTokenRepository(db: Kysely<Database> | DbExecutor): TokenRepository {
  return {
    async insert(token) {
      await db
        .insertInto("tokens")
        .values({
          id: token.id,
          user_id: token.userId,
          kind: token.kind,
          token_hash: token.tokenHash,
          expires_at: token.expiresAt,
          metadata: token.metadata ?? {},
        })
        .execute();
    },

    async consumeByHash(kind, tokenHash, now) {
      const rows = await db
        .updateTable("tokens")
        .set({ used_at: now })
        .where("kind", "=", kind)
        .where("token_hash", "=", tokenHash)
        .where("used_at", "is", null)
        .where("expires_at", ">", now)
        .returning("user_id")
        .execute();
      return rows.length > 0 ? rows[0]!.user_id : null;
    },

    async findByHash(kind, tokenHash, now) {
      const row = await db
        .selectFrom("tokens")
        .select(["id", "user_id", "metadata"])
        .where("kind", "=", kind)
        .where("token_hash", "=", tokenHash)
        .where("used_at", "is", null)
        .where("expires_at", ">", now)
        .executeTakeFirst();
      if (!row) {
        return null;
      }
      return { id: row.id, userId: row.user_id, metadata: row.metadata ?? {} };
    },

  async updateMetadata(id, patch) {
    // Merge into the existing JSONB document so a partial patch cannot wipe sibling keys.
    const rows = await db
      .updateTable("tokens")
      .set({ metadata: sql`metadata || ${JSON.stringify(patch)}::jsonb` })
      .where("id", "=", id)
      .returning("id")
      .execute();
    return rows.length > 0;
  },

    async incrementMfaFailures(id) {
      const rows = await db
        .updateTable("tokens")
        .set({ mfa_failed_attempts: sql`mfa_failed_attempts + 1` })
        .where("id", "=", id)
        .where("used_at", "is", null)
        .returning("mfa_failed_attempts")
        .execute();
      return rows.length > 0 ? rows[0]!.mfa_failed_attempts : null;
    },

  async markUsed(id, now) {
    await db
      .updateTable("tokens")
      .set({ used_at: now })
      .where("id", "=", id)
      .where("used_at", "is", null)
      .execute();
  },

  async invalidateAll(kind, userId) {
    const rows = await db
      .updateTable("tokens")
      .set({ used_at: new Date() })
      .where("kind", "=", kind)
      .where("user_id", "=", userId)
      .where("used_at", "is", null)
      .returning("id")
      .execute();
    return rows.length;
  },
  };
}
