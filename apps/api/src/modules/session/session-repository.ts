import type { Kysely, Selectable } from "kysely";
import type { Database, SessionsTable } from "../../infrastructure/db/database.js";

type SessionRow = Selectable<SessionsTable>;

export interface SessionRecord {
  id: string;
  userId: string;
  createdAt: Date;
  expiresAt: Date;
  lastUsedAt: Date;
  ipAddress: string | null;
  userAgent: string | null;
  revokedAt: Date | null;
}

export interface NewSession {
  id: string;
  userId: string;
  tokenHash: string;
  expiresAt: Date;
  ipAddress?: string;
  userAgent?: string;
}

export interface SessionRepository {
  insert(session: NewSession): Promise<SessionRecord>;
  findByHash(tokenHash: string): Promise<SessionRecord | null>;
  touch(id: string, now: Date): Promise<void>;
  revoke(id: string, userId: string): Promise<boolean>;
  revokeAll(userId: string): Promise<number>;
  revokeAllExcept(userId: string, keepId: string): Promise<number>;
  listByUser(userId: string): Promise<SessionRecord[]>;
}

function toSessionRecord(row: SessionRow): SessionRecord {
  return {
    id: row.id,
    userId: row.user_id,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    lastUsedAt: row.last_used_at,
    ipAddress: row.ip_address,
    userAgent: row.user_agent,
    revokedAt: row.revoked_at,
  };
}

export function createSessionRepository(db: Kysely<Database>): SessionRepository {
  return {
    async insert(session) {
      const row = await db
        .insertInto("sessions")
        .values({
          id: session.id,
          user_id: session.userId,
          token_hash: session.tokenHash,
          expires_at: session.expiresAt,
          ip_address: session.ipAddress ?? null,
          user_agent: session.userAgent ?? null,
        })
        .returningAll()
        .executeTakeFirstOrThrow();
      return toSessionRecord(row);
    },

    async findByHash(tokenHash) {
      const row = await db
        .selectFrom("sessions")
        .selectAll()
        .where("token_hash", "=", tokenHash)
        .executeTakeFirst();
      return row ? toSessionRecord(row) : null;
    },

    async touch(id, now) {
      await db
        .updateTable("sessions")
        .set({ last_used_at: now })
        .where("id", "=", id)
        .execute();
    },

    async revoke(id, userId) {
      const rows = await db
        .updateTable("sessions")
        .set({ revoked_at: new Date() })
        .where("id", "=", id)
        .where("user_id", "=", userId)
        .returning("id")
        .execute();
      return rows.length > 0;
    },

    async revokeAll(userId) {
      const rows = await db
        .updateTable("sessions")
        .set({ revoked_at: new Date() })
        .where("user_id", "=", userId)
        .where("revoked_at", "is", null)
        .returning("id")
        .execute();
      return rows.length;
    },

    async revokeAllExcept(userId, keepId) {
      const rows = await db
        .updateTable("sessions")
        .set({ revoked_at: new Date() })
        .where("user_id", "=", userId)
        .where("id", "!=", keepId)
        .where("revoked_at", "is", null)
        .returning("id")
        .execute();
      return rows.length;
    },

    async listByUser(userId) {
      const rows = await db
        .selectFrom("sessions")
        .selectAll()
        .where("user_id", "=", userId)
        .orderBy("created_at", "desc")
        .execute();
      return rows.map(toSessionRecord);
    },
  };
}
