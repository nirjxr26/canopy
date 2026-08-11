import { beforeEach, describe, expect, it } from "vitest";
import { Kysely } from "kysely";
import { loadConfig } from "../src/infrastructure/config/config.js";
import { createLogger } from "../src/infrastructure/logging/logger.js";
import { createDb } from "../src/infrastructure/db/database.js";
import type { Database } from "../src/infrastructure/db/database.js";
import { createOutboxRepository } from "../src/modules/email/outbox-repository.js";
import {
  createEmailService,
  type EmailMessage,
  type EmailProvider,
} from "../src/modules/email/email-service.js";
import { describeDb, resetTestDatabase, TEST_DATABASE_URL, TEST_MFA_KEY } from "./helpers/db.js";
import { migrateToLatest } from "../src/infrastructure/db/migrate.js";

const BASE = 1_000;

class RecordingProvider implements EmailProvider {
  readonly kind = "console" as const;
  readonly sent: EmailMessage[] = [];
  async send(message: EmailMessage): Promise<void> {
    this.sent.push(message);
  }
}

class FailingProvider implements EmailProvider {
  readonly kind = "smtp" as const;
  readonly attempts: string[] = [];
  async send(message: EmailMessage): Promise<void> {
    this.attempts.push(message.to);
    throw new Error("smtp down");
  }
}

function makeTestConfig(overrides: Record<string, string> = {}) {
  return loadConfig({
    NODE_ENV: "test",
    DATABASE_URL: TEST_DATABASE_URL,
    FRONTEND_URL: "http://localhost:5173",
    AUTH_BASE_URL: "http://localhost:3000",
    MFA_ENCRYPTION_KEYS: TEST_MFA_KEY,
    ARGON_MEMORY_KIB: "8192",
    ARGON_TIME_COST: "1",
    ARGON_PARALLELISM: "1",
    EMAIL_RETRY_BACKOFF_MS: String(BASE),
    ...overrides,
  });
}

interface OutboxHarness {
  db: Kysely<Database>;
  pool: { end(): Promise<void> };
  emails: ReturnType<typeof createEmailService>;
}

function makeHarness(provider: EmailProvider, overrides: Record<string, string> = {}): OutboxHarness & {
  provider: EmailProvider;
} {
  const config = makeTestConfig(overrides);
  const logger = createLogger("silent");
  const { db, pool } = createDb(config);
  const outbox = createOutboxRepository(db);
  const emails = createEmailService({ outbox, provider, config });
  return { db, pool, emails, provider };
}

describeDb("email outbox", () => {
  beforeEach(async () => {
    await resetTestDatabase();
    await migrateToLatest({ databaseUrl: TEST_DATABASE_URL, dbPoolMin: 2, dbPoolMax: 10 });
  });

  it("sends due messages and marks them sent", async () => {
    const harness = makeHarness(new RecordingProvider());
    const provider = harness.provider as RecordingProvider;
    await harness.emails.queue("verify-email", "outbox-1@example.com", "tok-one");
    await harness.emails.queue("password-reset", "outbox-2@example.com", "tok-two");
    const sent = await harness.emails.processDueEmails();
    expect(sent).toBe(2);
    expect(provider.sent.map((m) => m.to)).toEqual(["outbox-1@example.com", "outbox-2@example.com"]);
    expect(provider.sent[0]!.body).toContain("verify-email?token=tok-one");
    expect(provider.sent[1]!.body).toContain("reset-password?token=tok-two");
    expect(provider.sent[0]!.html).toContain("verify-email?token=tok-one");
    expect(provider.sent[1]!.html).toContain("reset-password?token=tok-two");
    expect(provider.sent[0]!.html).toContain("<a href=");
    const rows = await harness.db.selectFrom("email_outbox").selectAll().execute();
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row.sent_at).not.toBeNull();
      expect(row.html_body).not.toBeNull();
    }
    await harness.pool.end();
  });

  it("records failures with exponential backoff and retries later", async () => {
    const harness = makeHarness(new FailingProvider());
    const provider = harness.provider as FailingProvider;
    await harness.emails.queue("verify-email", "outbox-fail@example.com", "tok-fail");
    const first = await harness.emails.processDueEmails();
    expect(first).toBe(0);
    expect(provider.attempts).toHaveLength(1);
    let row = await harness.db
      .selectFrom("email_outbox")
      .selectAll()
      .where("recipient", "=", "outbox-fail@example.com")
      .executeTakeFirstOrThrow();
    expect(row.attempt_count).toBe(1);
    const firstNextAttempt = row.next_attempt_at.getTime();
    expect(firstNextAttempt).toBeGreaterThan(Date.now());

    await harness.emails.processDueEmails(new Date(firstNextAttempt + 1));
    row = await harness.db
      .selectFrom("email_outbox")
      .selectAll()
      .where("recipient", "=", "outbox-fail@example.com")
      .executeTakeFirstOrThrow();
    expect(row.attempt_count).toBe(2);
    expect(row.next_attempt_at.getTime()).toBe(firstNextAttempt + 1 + BASE * 2 ** 1);
    await harness.pool.end();
  });

  it("stops retrying at max attempts (dead letter)", async () => {
    const harness = makeHarness(new FailingProvider(), { EMAIL_RETRY_MAX: "2" });
    const provider = harness.provider as FailingProvider;
    await harness.emails.queue("verify-email", "outbox-dead@example.com", "tok-dead");
    await harness.emails.processDueEmails();
    let row = await harness.db
      .selectFrom("email_outbox")
      .selectAll()
      .where("recipient", "=", "outbox-dead@example.com")
      .executeTakeFirstOrThrow();
    await harness.emails.processDueEmails(new Date(row.next_attempt_at.getTime() + 1));
    row = await harness.db
      .selectFrom("email_outbox")
      .selectAll()
      .where("recipient", "=", "outbox-dead@example.com")
      .executeTakeFirstOrThrow();
    expect(row.attempt_count).toBe(2);
    const third = await harness.emails.processDueEmails(new Date(row.next_attempt_at.getTime() + 1));
    expect(third).toBe(0);
    expect(provider.attempts).toHaveLength(2);
    await harness.pool.end();
  });
});
