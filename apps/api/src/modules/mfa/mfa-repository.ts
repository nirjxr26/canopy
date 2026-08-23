import type { Kysely } from "kysely";
import type { Database, DbExecutor } from "../../infrastructure/db/database.js";
import { createId } from "../../infrastructure/crypto/ulid.js";

export interface MfaCredential {
  id: string;
  userId: string;
  method: string;
  secretEncrypted: string;
  keyVersion: number;
  enabledAt: Date | null;
}

export interface MfaRepository {
  findEnabledByUser(userId: string): Promise<MfaCredential | null>;
  /** Pending enrollment: a row with enabled_at = NULL (spec §4). */
  findPendingByUser(userId: string): Promise<MfaCredential | null>;
  /** Insert-or-replace the pending enrollment (UNIQUE(user_id, method)). */
  upsertPending(input: {
    userId: string;
    method: string;
    secretEncrypted: string;
    keyVersion: number;
  }): Promise<void>;
  /** Atomically flip the pending enrollment to enabled. */
  enablePending(userId: string, method: string, now: Date): Promise<boolean>;
  updateSecret(
    userId: string,
    method: string,
    patch: { secretEncrypted: string; keyVersion: number },
  ): Promise<boolean>;
  deleteByUser(userId: string): Promise<void>;
  insertRecoveryCodes(userId: string, codeHashes: string[]): Promise<void>;
  consumeRecoveryCode(userId: string, codeHash: string): Promise<boolean>;
  deleteRecoveryCodes(userId: string): Promise<void>;
}

export function createMfaRepository(db: Kysely<Database> | DbExecutor): MfaRepository {
  return {
    async findEnabledByUser(userId) {
      const row = await db
        .selectFrom("mfa_credentials")
        .select(["id", "user_id", "method", "secret_encrypted", "key_version", "enabled_at"])
        .where("user_id", "=", userId)
        .where("enabled_at", "is not", null)
        .where("method", "=", "totp")
        .executeTakeFirst();
      if (!row) {
        return null;
      }
      return {
        id: row.id,
        userId: row.user_id,
        method: row.method,
        secretEncrypted: row.secret_encrypted,
        keyVersion: row.key_version,
        enabledAt: row.enabled_at,
      };
    },

    async findPendingByUser(userId) {
      const row = await db
        .selectFrom("mfa_credentials")
        .select(["id", "user_id", "method", "secret_encrypted", "key_version", "enabled_at"])
        .where("user_id", "=", userId)
        .where("enabled_at", "is", null)
        .where("method", "=", "totp")
        .executeTakeFirst();
      if (!row) {
        return null;
      }
      return {
        id: row.id,
        userId: row.user_id,
        method: row.method,
        secretEncrypted: row.secret_encrypted,
        keyVersion: row.key_version,
        enabledAt: row.enabled_at,
      };
    },

    async upsertPending(input) {
      await db
        .insertInto("mfa_credentials")
        .values({
          id: createId("mfac"),
          user_id: input.userId,
          method: input.method,
          secret_encrypted: input.secretEncrypted,
          key_version: input.keyVersion,
          enabled_at: null,
        })
        .onConflict((oc) =>
          oc.columns(["user_id", "method"]).doUpdateSet({
            secret_encrypted: input.secretEncrypted,
            key_version: input.keyVersion,
            enabled_at: null,
          }),
        )
        .execute();
    },

    async enablePending(userId, method, now) {
      const rows = await db
        .updateTable("mfa_credentials")
        .set({ enabled_at: now })
        .where("user_id", "=", userId)
        .where("method", "=", method)
        .where("enabled_at", "is", null)
        .returning("id")
        .execute();
      return rows.length > 0;
    },

    async updateSecret(userId, method, patch) {
      const rows = await db
        .updateTable("mfa_credentials")
        .set({ secret_encrypted: patch.secretEncrypted, key_version: patch.keyVersion })
        .where("user_id", "=", userId)
        .where("method", "=", method)
        .returning("id")
        .execute();
      return rows.length > 0;
    },

    async deleteByUser(userId) {
      await db.deleteFrom("mfa_credentials").where("user_id", "=", userId).execute();
    },

    async insertRecoveryCodes(userId, codeHashes) {
      await db
        .insertInto("recovery_codes")
        .values(codeHashes.map((codeHash) => ({ id: createId("rc"), user_id: userId, code_hash: codeHash })))
        .execute();
    },

    async consumeRecoveryCode(userId, codeHash) {
      const rows = await db
        .updateTable("recovery_codes")
        .set({ used_at: new Date() })
        .where("user_id", "=", userId)
        .where("code_hash", "=", codeHash)
        .where("used_at", "is", null)
        .returning("id")
        .execute();
      return rows.length > 0;
    },

    async deleteRecoveryCodes(userId) {
      await db.deleteFrom("recovery_codes").where("user_id", "=", userId).execute();
    },
  };
}
