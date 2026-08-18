import { createLogger } from "../infrastructure/logging/logger.js";
import { configFromEnv } from "../infrastructure/config/env.js";
import { createDb } from "../infrastructure/db/database.js";
import { createRateLimiter } from "../infrastructure/ratelimit/index.js";
import { createPasswordHasher } from "../infrastructure/crypto/password.js";
import { createUserRepository } from "../modules/identity/user-repository.js";
import { createUserService } from "../modules/identity/user-service.js";
import { createTokenRepository } from "../modules/identity/token-repository.js";
import { createTokenService } from "../modules/identity/token-service.js";
import { createSessionRepository } from "../modules/session/session-repository.js";
import { createSessionService } from "../modules/session/session-service.js";
import { createMfaRepository } from "../modules/mfa/mfa-repository.js";
import { createMfaService } from "../modules/mfa/mfa-service.js";
import { createOutboxRepository } from "../modules/email/outbox-repository.js";
import {
  createConsoleEmailProvider,
  createEmailService,
  createSmtpEmailProvider,
  OUTBOX_POLL_MS,
} from "../modules/email/email-service.js";
import { createSecurityEventRepository } from "../modules/security-events/security-events-repository.js";
import { createSecurityEventService } from "../modules/security-events/security-events-service.js";
import { validateJwtKey } from "../modules/jwt/jwt-service.js";
import { createApp } from "./app.js";

const config = configFromEnv();
const logger = createLogger(config.logLevel);
const { pool, db } = createDb(config);
const hasher = createPasswordHasher({
  memoryCostKiB: config.argonMemoryKib,
  timeCost: config.argonTimeCost,
  parallelism: config.argonParallelism,
  hashLength: config.argonHashLength,
});
const limiter = createRateLimiter(config);
const users = createUserService(createUserRepository(db), hasher);
const sessions = createSessionService(createSessionRepository(db), { getById: users.getById }, config);
const tokens = createTokenService(createTokenRepository(db));
const mfa = createMfaService({
  repository: createMfaRepository(db),
  tokens,
  db,
  keys: config.mfaEncryptionKeys,
  issuer: config.jwtIssuer,
});
let emailProvider;
if (config.emailProvider === "smtp") {
  if (config.smtpUrl === undefined) {
    throw new Error("EMAIL_PROVIDER=smtp requires SMTP_URL");
  }
  emailProvider = createSmtpEmailProvider(logger, config.smtpUrl);
} else {
  emailProvider = createConsoleEmailProvider(logger);
}
const emails = createEmailService({
  outbox: createOutboxRepository(db),
  provider: emailProvider,
  config,
  keys: config.mfaEncryptionKeys,
  logger,
});
const securityEvents = createSecurityEventService(createSecurityEventRepository(db), logger);

if (config.jwtPrivateKey) {
  await validateJwtKey(config.jwtPrivateKey).catch((err: unknown) => {
    console.error("startup failed:", err);
    process.exit(1);
  });
}

const app = createApp({
  config,
  logger,
  db,
  hasher,
  limiter,
  users,
  sessions,
  tokens,
  emails,
  mfa,
  provider: emailProvider,
  keys: config.mfaEncryptionKeys,
  securityEvents,
});

const server = app.listen(config.port, () => {
  logger.info({ port: config.port, env: config.nodeEnv }, "api listening");
});
server.on("error", (err) => {
  logger.error({ err }, "server error");
  void shutdown("server-error");
});

const emailWorker = setInterval(() => {
  void emails.processDueEmails().catch((err: unknown) => {
    logger.error({ err }, "email outbox worker error");
  });
}, OUTBOX_POLL_MS);
emailWorker.unref();

let shutdownComplete = false;

async function shutdown(signal: string): Promise<void> {
  if (shutdownComplete) {
    return;
  }
  shutdownComplete = true;
  logger.info({ signal }, "shutting down");
  clearInterval(emailWorker);
  const forceExitTimer = setTimeout(() => {
    logger.error("graceful shutdown timed out; forcing exit");
    process.exit(1);
  }, 10_000);
  forceExitTimer.unref();
  server.close(async (closeErr) => {
    await limiter.dispose();
    await pool.end();
    process.exit(closeErr ? 1 : 0);
  });
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));