import "dotenv/config";
import pg from "pg";
import { loadConfig } from "../../../src/infrastructure/config/config.js";
import { decryptSecret } from "../../../src/infrastructure/crypto/cipher.js";

const { Pool } = pg;

const DATABASE_URL =
  process.env.DATABASE_URL ??
  process.env.TEST_DATABASE_URL ??
  "postgres://postgres:postgres@localhost:5432/auuth";

const pool = new Pool({ connectionString: DATABASE_URL, max: 2 });

export interface OutboxDbRow {
  id: number;
  recipient: string;
  subject: string;
  body: string;
  htmlBody: string | null;
  attemptCount: number;
  sentAt: string | null;
  createdAt: string;
}

export interface OutboxWaitOptions {
  timeoutMs?: number;
  pollMs?: number;
}

const DEFAULT_TIMEOUT_MS = 45_000;
const DEFAULT_POLL_MS = 500;

export async function findOutboxRow(
  recipient: string,
  subject: string,
): Promise<OutboxDbRow | null> {
  const result = await pool.query(
    `SELECT id, recipient, subject, body, html_body AS "htmlBody",
            attempt_count AS "attemptCount", sent_at AS "sentAt", created_at AS "createdAt"
       FROM email_outbox
      WHERE recipient = $1 AND subject = $2
      ORDER BY id DESC
      LIMIT 1`,
    [recipient, subject],
  );
  return (result.rows[0] as OutboxDbRow | undefined) ?? null;
}

export async function countOutboxRows(recipient: string, subject: string): Promise<number> {
  const result = await pool.query(
    `SELECT COUNT(*)::int AS count FROM email_outbox WHERE recipient = $1 AND subject = $2`,
    [recipient, subject],
  );
  return result.rows[0].count as number;
}

export async function waitForOutboxRow(
  recipient: string,
  subject: string,
  options: OutboxWaitOptions = {},
): Promise<OutboxDbRow> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pollMs = options.pollMs ?? DEFAULT_POLL_MS;
  const deadline = Date.now() + timeoutMs;
  let last: OutboxDbRow | null = null;
  while (Date.now() < deadline) {
    last = await findOutboxRow(recipient, subject);
    if (last !== null) {
      return last;
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  throw new Error(`outbox row not found for ${recipient} / ${subject} within ${timeoutMs}ms`);
}

export async function waitForOutboxDelivery(
  recipient: string,
  subject: string,
  options: OutboxWaitOptions = {},
): Promise<OutboxDbRow> {
  const timeoutMs = options.timeoutMs ?? 60_000;
  const pollMs = options.pollMs ?? 500;
  const deadline = Date.now() + timeoutMs;
  let last: OutboxDbRow | null = null;
  while (Date.now() < deadline) {
    last = await findOutboxRow(recipient, subject);
    if (last !== null && last.sentAt !== null) {
      return last;
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  throw new Error(
    `email to ${recipient} / ${subject} was never delivered (sent_at null, last row id=${
      last?.id ?? "none"
    }) within ${timeoutMs}ms`,
  );
}

function unsealBody(body: string): string {
  if (/^v\d+:/.test(body)) {
    const config = loadConfig(process.env as Record<string, string>);
    const parsed = JSON.parse(decryptSecret(body, config.mfaEncryptionKeys)) as {
      text: string;
    };
    return parsed.text;
  }
  return body;
}

export function extractTokenFromEmail(row: OutboxDbRow): string {
  const body = unsealBody(row.body);
  const match = body.match(/[?&]token=([A-Za-z0-9_-]+)/);
  if (match === null) {
    throw new Error(`no token found in email body for ${row.recipient} / ${row.subject}`);
  }
  return match[1]!;
}