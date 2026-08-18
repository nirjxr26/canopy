import type { Kysely } from "kysely";
import type { Database, DbExecutor } from "../../infrastructure/db/database.js";

export interface SecurityEventInput {
  eventType: string;
  userId?: string;
  actor?: "USER" | "SYSTEM";
  ipAddress?: string;
  userAgent?: string;
  correlationId?: string;
  metadata?: Record<string, unknown>;
}

export interface SecurityEventRepository {
  insert(event: SecurityEventInput): Promise<void>;
}

export function createSecurityEventRepository(db: Kysely<Database> | DbExecutor): SecurityEventRepository {
  return {
    async insert(event) {
      await db
        .insertInto("security_events")
        .values({
          event_type: event.eventType,
          user_id: event.userId ?? null,
          actor: event.actor ?? "USER",
          ip_address: event.ipAddress ?? null,
          user_agent: event.userAgent ?? null,
          correlation_id: event.correlationId ?? null,
          metadata: event.metadata ?? {},
        })
        .execute();
    },
  };
}