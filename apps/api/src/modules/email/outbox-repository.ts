import type { Kysely } from "kysely";
import type { Database } from "../../infrastructure/db/database.js";

export interface OutboxMessage {
  id: number;
  recipient: string;
  subject: string;
  body: string;
  htmlBody: string | null;
  attemptCount: number;
}

export interface NewOutboxMessage {
  recipient: string;
  subject: string;
  body: string;
  htmlBody: string | null;
}

export interface OutboxRepository {
  insert(message: NewOutboxMessage): Promise<void>;
  pickDue(now: Date, maxAttempts: number, limit: number): Promise<OutboxMessage[]>;
  markSent(id: number, now: Date): Promise<void>;
  recordFailure(id: number, nextAttemptAt: Date): Promise<void>;
}

export function createOutboxRepository(db: Kysely<Database>): OutboxRepository {
  return {
    async insert(message) {
      await db
        .insertInto("email_outbox")
        .values({
          recipient: message.recipient,
          subject: message.subject,
          body: message.body,
          html_body: message.htmlBody,
          attempt_count: 0,
          next_attempt_at: new Date(),
        })
        .execute();
    },

    async pickDue(now, maxAttempts, limit) {
      const rows = await db
        .selectFrom("email_outbox")
        .selectAll()
        .where("next_attempt_at", "<=", now)
        .where("sent_at", "is", null)
        .where("attempt_count", "<", maxAttempts)
        .orderBy("next_attempt_at", "asc")
        .limit(limit)
        .execute();
      return rows.map((row) => ({
        id: row.id,
        recipient: row.recipient,
        subject: row.subject,
        body: row.body,
        htmlBody: row.html_body,
        attemptCount: row.attempt_count,
      }));
    },

    async markSent(id, now) {
      await db
        .updateTable("email_outbox")
        .set({ sent_at: now })
        .where("id", "=", id)
        .execute();
    },

    async recordFailure(id, nextAttemptAt) {
      await db
        .updateTable("email_outbox")
        .set((eb) => ({
          attempt_count: eb("attempt_count", "+", 1),
          next_attempt_at: nextAttemptAt,
        }))
        .where("id", "=", id)
        .execute();
    },
  };
}
