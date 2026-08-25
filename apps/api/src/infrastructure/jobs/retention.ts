import type pino from "pino";
import type { Database } from "../db/database.js";
import type { Kysely } from "kysely";
import { sql } from "kysely";

export interface RetentionStats {
  cutoff: Date;
  anonymizedSessions: number;
  anonymizedEvents: number;
  purgedTokens: number;
  purgedSessions: number;
  purgedOutbox: number;
}

export interface RetentionJob {
  /** Runs one sweep. Idempotent — safe to call repeatedly (spec §6.13). */
  runOnce(now?: Date): Promise<RetentionStats>;
  /** Starts the hourly in-process scheduler; returns a stop() that also flushes the in-flight run. */
  start(logger: pino.Logger, intervalMs?: number): { stop(): Promise<void> };
}

const BATCH_SIZE = 5_000;

/**
 * §6.13 data retention (R-29):
 *  - anonymize IP/UA past RETENTION_DAYS
 *  - purge dead tokens/sessions and SENT outbox rows past the window
 *
 * R1: every batch runs in its own transaction with statement_timeout disabled,
 * so large tables cannot trip the pool-wide 5 s timeout.
 * P1: mutations are batched to keep lock windows short.
 * Idempotent throughout.
 */
export function createRetentionJob(db: Kysely<Database>, opts: { retentionDays: number }): RetentionJob {
  async function withoutTimeout<T>(fn: (tx: Kysely<Database>) => Promise<T>): Promise<T> {
    return db.transaction().execute(async (tx) => {
      await sql`SET LOCAL statement_timeout = 0`.execute(tx);
      return fn(tx);
    });
  }

  /** Repeats a batched mutation until it reports a short batch; returns total. */
  async function drain(mutateBatch: () => Promise<number>): Promise<number> {
    let total = 0;
    for (;;) {
      const n = await mutateBatch();
      total += n;
      if (n < BATCH_SIZE) break;
    }
    return total;
  }

  async function runOnce(now = new Date()): Promise<RetentionStats> {
    const cutoff = new Date(now.getTime() - opts.retentionDays * 86_400_000);

    const anonymizeSessions = () =>
      withoutTimeout(async (tx) => {
        const rows = await tx
          .selectFrom("sessions")
          .select("id")
          .where("created_at", "<", cutoff)
          .where((eb) => eb.or([eb("ip_address", "is not", null), eb("user_agent", "is not", null)]))
          .limit(BATCH_SIZE)
          .execute();
        if (rows.length === 0) return 0;
        const r = await tx
          .updateTable("sessions")
          .set({ ip_address: null, user_agent: null })
          .where("id", "in", rows.map((r2) => r2.id))
          .executeTakeFirst();
        return Number(r.numUpdatedRows);
      });

    const anonymizeEvents = () =>
      withoutTimeout(async (tx) => {
        const rows = await tx
          .selectFrom("security_events")
          .select("id")
          .where("occurred_at", "<", cutoff)
          .where((eb) => eb.or([eb("ip_address", "is not", null), eb("user_agent", "is not", null)]))
          .limit(BATCH_SIZE)
          .execute();
        if (rows.length === 0) return 0;
        const r = await tx
          .updateTable("security_events")
          .set({ ip_address: null, user_agent: null })
          .where("id", "in", rows.map((r2) => r2.id))
          .executeTakeFirst();
        return Number(r.numUpdatedRows);
      });

    const purgeTokens = () =>
      withoutTimeout(async (tx) => {
        const rows = await tx
          .selectFrom("tokens")
          .select("id")
          .where("expires_at", "<", cutoff)
          .limit(BATCH_SIZE)
          .execute();
        if (rows.length === 0) return 0;
        const r = await tx
          .deleteFrom("tokens")
          .where("id", "in", rows.map((r2) => r2.id))
          .executeTakeFirst();
        return Number(r.numDeletedRows);
      });

    const purgeSessions = () =>
      withoutTimeout(async (tx) => {
        const rows = await tx
          .selectFrom("sessions")
          .select("id")
          .where("created_at", "<", cutoff)
          .where((eb) => eb.or([eb("revoked_at", "is not", null), eb("expires_at", "<", now)]))
          .limit(BATCH_SIZE)
          .execute();
        if (rows.length === 0) return 0;
        const r = await tx
          .deleteFrom("sessions")
          .where("id", "in", rows.map((r2) => r2.id))
          .executeTakeFirst();
        return Number(r.numDeletedRows);
      });

    // SC1: sent outbox rows are transport artifacts — drop them past the window.
    const purgeOutbox = () =>
      withoutTimeout(async (tx) => {
        const rows = await tx
          .selectFrom("email_outbox")
          .select("id")
          .where("sent_at", "is not", null)
          .where("created_at", "<", cutoff)
          .limit(BATCH_SIZE)
          .execute();
        if (rows.length === 0) return 0;
        const r = await tx
          .deleteFrom("email_outbox")
          .where("id", "in", rows.map((r2) => r2.id))
          .executeTakeFirst();
        return Number(r.numDeletedRows);
      });

    return {
      cutoff,
      anonymizedSessions: await drain(anonymizeSessions),
      anonymizedEvents: await drain(anonymizeEvents),
      purgedTokens: await drain(purgeTokens),
      purgedSessions: await drain(purgeSessions),
      purgedOutbox: await drain(purgeOutbox),
    };
  }

  function start(logger: pino.Logger, intervalMs = 3_600_000) {
    let stopped = false;
    let inFlight: Promise<void> = Promise.resolve();
    const tick = () => {
      inFlight = inFlight.then(async () => {
        if (stopped) return;
        try {
          const stats = await runOnce();
          const touched =
            stats.anonymizedSessions +
            stats.anonymizedEvents +
            stats.purgedTokens +
            stats.purgedSessions +
            stats.purgedOutbox;
          if (touched > 0) logger.info(stats, "retention sweep applied");
        } catch (err) {
          logger.error({ err }, "retention sweep failed");
        }
      });
      return inFlight;
    };
    void tick(); // sweep once at startup
    const timer = setInterval(() => void tick(), intervalMs);
    timer.unref();
    return {
      async stop() {
        stopped = true;
        clearInterval(timer);
        await inFlight.catch(() => undefined);
      },
    };
  }

  return { runOnce, start };
}
