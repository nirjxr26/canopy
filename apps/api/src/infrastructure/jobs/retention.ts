import type pino from "pino";
import type { Database } from "../db/database.js";
import type { Kysely } from "kysely";

export interface RetentionStats {
  cutoff: Date;
  anonymizedSessions: number;
  anonymizedEvents: number;
  purgedTokens: number;
  purgedSessions: number;
}

export interface RetentionJob {
  /** Runs one sweep. Idempotent — safe to call repeatedly (spec §6.13). */
  runOnce(now?: Date): Promise<RetentionStats>;
  /** Starts the hourly in-process scheduler; returns a stop() that also flushes the in-flight run. */
  start(logger: pino.Logger, intervalMs?: number): { stop(): Promise<void> };
}

/**
 * §6.13 data retention (R-29): anonymize IP/UA past RETENTION_DAYS and purge
 * dead token/session rows. All statements are idempotent; failures are logged
 * by the scheduler and never crash the process.
 */
export function createRetentionJob(db: Kysely<Database>, opts: { retentionDays: number }): RetentionJob {
  async function runOnce(now = new Date()): Promise<RetentionStats> {
    const cutoff = new Date(now.getTime() - opts.retentionDays * 86_400_000);

    // Anonymize identifying columns on old rows (only where something is set,
    // so re-runs are no-ops).
    const sessionsAnon = await db
      .updateTable("sessions")
      .set({ ip_address: null, user_agent: null })
      .where("created_at", "<", cutoff)
      .where((eb) =>
        eb.or([eb("ip_address", "is not", null), eb("user_agent", "is not", null)]),
      )
      .executeTakeFirst();

    const eventsAnon = await db
      .updateTable("security_events")
      .set({ ip_address: null, user_agent: null })
      .where("occurred_at", "<", cutoff)
      .where((eb) =>
        eb.or([eb("ip_address", "is not", null), eb("user_agent", "is not", null)]),
      )
      .executeTakeFirst();

    // Purge tokens that expired beyond the retention window.
    const purgedTokens = await db
      .deleteFrom("tokens")
      .where("expires_at", "<", cutoff)
      .executeTakeFirst();

    // Purge sessions that are dead (revoked or expired) and older than the window.
    const purgedSessions = await db
      .deleteFrom("sessions")
      .where("created_at", "<", cutoff)
      .where((eb) =>
        eb.or([eb("revoked_at", "is not", null), eb("expires_at", "<", now)]),
      )
      .executeTakeFirst();

    return {
      cutoff,
      anonymizedSessions: Number(sessionsAnon.numUpdatedRows),
      anonymizedEvents: Number(eventsAnon.numUpdatedRows),
      purgedTokens: Number(purgedTokens.numDeletedRows),
      purgedSessions: Number(purgedSessions.numDeletedRows),
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
          if (
            stats.anonymizedSessions + stats.anonymizedEvents + stats.purgedTokens + stats.purgedSessions >
            0
          ) {
            logger.info(stats, "retention sweep applied");
          }
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
