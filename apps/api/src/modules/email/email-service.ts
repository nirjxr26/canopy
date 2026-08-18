import type pino from "pino";
import nodemailer from "nodemailer";
import type { Config, EncryptionKeyEntry } from "../../infrastructure/config/config.js";
import { decryptSecret, encryptSecret } from "../../infrastructure/crypto/cipher.js";
import { createId } from "../../infrastructure/crypto/ulid.js";
import type { OutboxRepository } from "./outbox-repository.js";

export const OUTBOX_POLL_MS = 15_000;
const OUTBOX_BATCH_SIZE = 100;
export const EMAIL_LEASE_MS = 5 * 60_000;

export interface EmailMessage {
  from: string;
  to: string;
  subject: string;
  body: string;
  html?: string;
}

export interface EmailProvider {
  kind: "console" | "smtp";
  send(message: EmailMessage): Promise<void>;
}

export function createConsoleEmailProvider(logger: pino.Logger): EmailProvider {
  return {
    kind: "console",
    async send(message) {
      logger.info(
        { from: message.from, to: message.to, subject: message.subject },
        `email outbox: sending to ${message.to} — subject: ${message.subject}`,
      );
      logger.debug({ body: message.body }, "email outbox body");
    },
  };
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("<", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;");
}

function normalizeFrontendUrlForProduction(url: string): string {
  return url.replace(/^http:\/\//i, "https://");
}

function normalizeFrontendUrlForDevelopment(url: string): string {
  return url;
}

function renderEmailHtml(deps: {
  heading: string;
  url: string;
  buttonLabel: string;
  expiryNote: string;
}): string {
  const { heading, url, buttonLabel, expiryNote } = deps;
  const href = escapeHtml(url);
  return (
    `<!doctype html><html><body style="margin:0;padding:0;background:#f4f5f7;font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif">` +
    `<div style="max-width:480px;margin:40px auto;background:#ffffff;border-radius:12px;padding:32px;border:1px solid #e6e8ee">` +
    `<div style="font-size:20px;font-weight:700;color:#0b0d12">SentinelX</div>` +
    `<h1 style="font-size:18px;color:#0b0d12;margin:24px 0 8px">${escapeHtml(heading)}</h1>` +
    `<p style="color:#5b6472;font-size:14px;line-height:1.6;margin:0 0 24px">To continue, open the link below. You can also copy and paste it into your browser.</p>` +
    `<a href="${href}" style="display:inline-block;background:#6d8dff;color:#ffffff;text-decoration:none;font-weight:600;padding:12px 24px;border-radius:8px;font-size:14px">${escapeHtml(buttonLabel)}</a>` +
    `<p style="color:#9aa3b2;font-size:12px;line-height:1.5;margin:24px 0 0;word-break:break-all">${href}</p>` +
    `<p style="color:#9aa3b2;font-size:12px;line-height:1.5;margin:12px 0 0">${escapeHtml(expiryNote)} If you didn't request this, you can safely ignore this email.</p>` +
    `</div></body></html>`
  );
}

export function createSmtpEmailProvider(
  logger: pino.Logger,
  smtpUrl: string,
): EmailProvider {
  let transport: nodemailer.Transporter | null = null;
  let host: string;
  try {
    const parsed = new URL(smtpUrl);
    if (parsed.protocol !== "smtp:" && parsed.protocol !== "smtps:") {
      throw new Error(`SMTP_URL scheme must be "smtp:" or "smtps:", got "${parsed.protocol}"`);
    }
    host = parsed.hostname;
  } catch (err) {
    throw new Error(
      `Invalid SMTP_URL: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  return {
    kind: "smtp",
    async send(message) {
      transport ??= nodemailer.createTransport(smtpUrl); //NOSONAR
      const info = await transport.sendMail({
        from: message.from,
        to: message.to,
        subject: message.subject,
        text: message.body,
        html: message.html ?? message.body,
      });
      if (info.rejected.length > 0) {
        throw new Error(`SMTP rejected recipients: ${info.rejected.join(", ")}`);
      }
      logger.info(
        { to: message.to, subject: message.subject, host, messageId: info.messageId },
        "email sent via smtp",
      );
    },
  };
}

export type EmailKind = "verify-email" | "password-reset";

export interface EmailService {
  queue(
    kind: EmailKind,
    recipient: string,
    token: string,
  ): Promise<{ devLink: string | null }>;
  processDueEmails(now?: Date): Promise<number>;
}

const EMAIL_META: Record<EmailKind, { subject: string; buttonLabel: string; expiresIn: string }> = {
  "verify-email": { subject: "Verify your email", buttonLabel: "Verify email", expiresIn: "24 hours" },
  "password-reset": { subject: "Reset your password", buttonLabel: "Reset password", expiresIn: "30 minutes" },
};

export function createEmailService(deps: {
  outbox: OutboxRepository;
  provider: EmailProvider;
  config: Pick<Config, "nodeEnv" | "emailFrom" | "frontendUrl" | "emailRetryMax" | "emailRetryBackoffMs">;
  keys: readonly EncryptionKeyEntry[];
  logger: pino.Logger;
}): EmailService {
  const { outbox, provider, config, keys, logger } = deps;
  const workerId = createId("wk");

  function buildMessage(kind: EmailKind, recipient: string, token: string): {
    message: EmailMessage;
    url: string;
  } {
    const meta = EMAIL_META[kind];
    const path =
      kind === "verify-email"
        ? `/verify-email?token=${encodeURIComponent(token)}`
        : `/reset-password?token=${encodeURIComponent(token)}`;
    const frontendUrl =
      config.nodeEnv === "production"
        ? normalizeFrontendUrlForProduction(config.frontendUrl)
        : normalizeFrontendUrlForDevelopment(config.frontendUrl);
    const url = `${frontendUrl}${path}`;
    const expiryNote = `This link expires in ${meta.expiresIn}.`;
    const body =
      `${meta.subject}\n\n` +
      `Open this link to continue: ${url}\n` +
      `${expiryNote} If you didn't request this, you can ignore this email.`;
    const html = renderEmailHtml({
      heading: meta.subject,
      url,
      buttonLabel: meta.buttonLabel,
      expiryNote,
    });
    return {
      message: { from: config.emailFrom, to: recipient, subject: meta.subject, body, html },
      url,
    };
  }

  return {
    async queue(kind, recipient, token) {
      const { message, url } = buildMessage(kind, recipient, token);
      const sealed = encryptSecret(JSON.stringify({ text: message.body, html: message.html }), keys);
      const sealedUrl = encryptSecret(url, keys);
      await outbox.insert({
        recipient: message.to,
        subject: message.subject,
        body: sealed.encrypted,
        htmlBody: null,
        tokenRef: sealedUrl.encrypted,
        messageId: createId("eml"),
      });
      return { devLink: provider.kind === "console" ? url : null };
    },

    async processDueEmails(now = new Date()) {
      const due = await outbox.claim(
        now,
        config.emailRetryMax,
        OUTBOX_BATCH_SIZE,
        EMAIL_LEASE_MS,
        workerId,
      );
      let sent = 0;
      for (const message of due) {
        try {
          let body = message.body;
          let html = message.htmlBody ?? undefined;
          if (message.tokenRef !== null) {
            const payload = JSON.parse(decryptSecret(message.body, keys)) as {
              text: string;
              html?: string;
            };
            body = payload.text;
            html = payload.html;
          }
          await provider.send({
            from: config.emailFrom,
            to: message.recipient,
            subject: message.subject,
            body,
            html,
          });
          await outbox.markSent(message.id, now);
          sent += 1;
        } catch (err) {
          const backoff = config.emailRetryBackoffMs * 2 ** message.attemptCount;
          const failure = await outbox.recordFailure(
            message.id,
            new Date(now.getTime() + backoff),
            config.emailRetryMax,
          );
          if (failure?.status === "dead") {
            logger.error(
              {
                messageId: message.messageId,
                recipient: message.recipient,
                attempts: failure.attemptCount,
                error: err instanceof Error ? err.message : String(err),
              },
              "email outbox: message failed permanently",
            );
          }
        }
      }
      return sent;
    },
  };
}