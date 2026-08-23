import type { Kysely } from "kysely";
import { sql } from "kysely";
import type { Database, DbExecutor } from "../../infrastructure/db/database.js";

export interface OutboxMessage {
  id: number;
  recipient: string;
  subject: string;
  body: string;
  htmlBody: string | null;
  tokenRef: string | null;
  attemptCount: number;
  status: string;
  lockedUntil: Date | null;
  workerId: string | null;
  messageId: string;
}

export interface NewOutboxMessage {
  recipient: string;
  subject: string;
  body: string;
  htmlBody: string | null;
  tokenRef: string | null;
  messageId: string;
}

export interface OutboxRepository {
  insert(message: NewOutboxMessage): Promise<void>;
  claim(
    now: Date,
    maxAttempts: number,
    limit: number,
    leaseMs: number,
    workerId: string,
  ): Promise<OutboxMessage[]>;
  markSent(id: number, now: Date): Promise<void>;
  recordFailure(
    id: number,
    nextAttemptAt: Date,
    maxAttempts: number,
  ): Promise<{ status: string; attemptCount: number } | null>;
}

function toOutboxMessage(row: {
  id: number;
  recipient: string;
  subject: string;
  body: string;
  html_body: string | null;
  token_ref: string | null;
  attempt_count: number;
  status: string;
  locked_until: Date | null;
  worker_id: string | null;
  message_id: string;
}): OutboxMessage {
  return {
    id: row.id,
    recipient: row.recipient,
    subject: row.subject,
    body: row.body,
    htmlBody: row.html_body,
    tokenRef: row.token_ref,
    attemptCount: row.attempt_count,
    status: row.status,
    lockedUntil: row.locked_until,
    workerId: row.worker_id,
    messageId: row.message_id,
  };
}

export function createOutboxRepository(db: Kysely<Database> | DbExecutor): OutboxRepository {
  return {
    async insert(message) {
      await db
        .insertInto("email_outbox")
        .values({
          recipient: message.recipient,
          subject: message.subject,
          body: message.body,
          html_body: message.htmlBody,
          token_ref: message.tokenRef,
          message_id: message.messageId,
          status: "pending",
          attempt_count: 0,
          next_attempt_at: new Date(),
        })
        .execute();
    },

    async claim(now, maxAttempts, limit, leaseMs, workerId) {
      const rows = await db
        .updateTable("email_outbox")
        .set({
          status: "processing",
          locked_until: new Date(now.getTime() + leaseMs),
          worker_id: workerId,
        })
        .where("id", "in", (qb) =>
          qb
            .selectFrom("email_outbox")
            .select("id")
            .where((eb) =>
              eb.or([
                eb("status", "=", "pending"),
                eb.and([
                  eb("status", "=", "processing"),
                  eb("locked_until", "<", now),
                ]),
              ]),
            )
            .where("sent_at", "is", null)
            .where("next_attempt_at", "<=", now)
            .where("attempt_count", "<", maxAttempts)
            .orderBy("next_attempt_at", "asc")
            .limit(limit)
            .forUpdate()
            .skipLocked(),
        )
        .returningAll()
        .execute();
      return rows.map(toOutboxMessage);
    },

    async markSent(id, now) {
      await db
        .updateTable("email_outbox")
        .set({
          sent_at: now,
          status: "sent",
          locked_until: null,
          worker_id: null,
        })
        .where("id", "=", id)
        .execute();
    },

    async recordFailure(id, nextAttemptAt, maxAttempts) {
      const rows = await db
        .updateTable("email_outbox")
        .set((eb) => ({
          attempt_count: eb("attempt_count", "+", 1),
          next_attempt_at: nextAttemptAt,
          status: sql`CASE WHEN attempt_count + 1 >= ${maxAttempts} THEN 'dead' ELSE 'pending' END`,
          locked_until: null,
          worker_id: null,
        }))
        .where("id", "=", id)
        .returning(["status", "attempt_count"])
        .execute();
      const row = rows[0];
      return row === undefined ? null : { status: row.status, attemptCount: row.attempt_count };
    },
  };
}