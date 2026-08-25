import type pino from "pino";
import type { Config, EncryptionKeyEntry } from "../../infrastructure/config/config.js";
import type { PasswordHasher } from "../../infrastructure/crypto/password.js";
import type { DbExecutor } from "../../infrastructure/db/database.js";
import { createEmailService } from "../email/email-service.js";
import type { EmailProvider } from "../email/email-service.js";
import { createOutboxRepository } from "../email/outbox-repository.js";
import { createSessionRepository } from "../session/session-repository.js";
import { createTokenRepository } from "./token-repository.js";
import { createTokenService } from "./token-service.js";
import { createUserRepository } from "./user-repository.js";
import { createUserService } from "./user-service.js";
import type { RegisterInput } from "./user-service.js";
import type { BreachedPasswordChecker } from "../../infrastructure/crypto/breached-passwords.js";
import { createLocalBreachedPasswordChecker } from "../../infrastructure/crypto/breached-passwords.js";

export type SignupOutcome = "created" | "duplicate_active" | "duplicate_pending_renewed";

export interface SignupResult {
  outcome: SignupOutcome;
  /** Internal only — for the security-event log. Never leaves the API (§6.1). */
  userId?: string;
}

export interface AuthFlows {
  signup(input: RegisterInput): Promise<SignupResult>;
  verifyEmailToken(rawToken: string, now?: Date): Promise<string | null>;
  resetPassword(rawToken: string, newPassword: string, now?: Date): Promise<string | null>;
}

export function createAuthFlows(deps: {
  db: DbExecutor;
  hasher: PasswordHasher;
  config: Config;
  provider: EmailProvider;
  keys: readonly EncryptionKeyEntry[];
  logger: pino.Logger;
  breached?: BreachedPasswordChecker;
}): AuthFlows {
  const { db, hasher, config, provider, keys, logger } = deps;
  const breached = deps.breached ?? createLocalBreachedPasswordChecker();

  return {
    async signup(input) {
      return db.transaction().execute(async (tx) => {
        const users = createUserService(createUserRepository(tx), hasher, breached);
        const tokens = createTokenService(createTokenRepository(tx));
        const emails = createEmailService({
          outbox: createOutboxRepository(tx),
          provider,
          config,
          keys,
          logger,
        });
        const result = await users.register(input);
        const user = result.user;
        if (result.created && user !== null) {
          const token = await tokens.issue("EMAIL_VERIFICATION", user.id);
          await emails.queue("verify-email", user.email, token);
          return { outcome: "created", userId: user.id };
        }
        if (user?.status === "PENDING_VERIFICATION") {
          // Renew the pending verification: issuing a fresh link invalidates all
          // previous ones, so only the newest email works (§6.1, no flooding of
          // evergreen links).
          await tokens.invalidateAll("EMAIL_VERIFICATION", user.id);
          const token = await tokens.issue("EMAIL_VERIFICATION", user.id);
          await emails.queue("verify-email", user.email, token);
          return { outcome: "duplicate_pending_renewed", userId: user.id };
        }
        // Active/other state: send nothing — an attacker must not be able to
        // force emails to an already-active account.
        return { outcome: "duplicate_active", userId: user?.id };
      });
    },

    async verifyEmailToken(rawToken, now = new Date()) {
      return db.transaction().execute(async (tx) => {
        const users = createUserService(createUserRepository(tx), hasher, breached);
        const tokens = createTokenService(createTokenRepository(tx));
        const userId = await tokens.consume("EMAIL_VERIFICATION", rawToken, now);
        if (userId === null) {
          return null;
        }
        await users.verifyEmail(userId, now);
        return userId;
      });
    },

    async resetPassword(rawToken, newPassword, now = new Date()) {
      return db.transaction().execute(async (tx) => {
        const users = createUserService(createUserRepository(tx), hasher, breached);
        const tokens = createTokenService(createTokenRepository(tx));
        const sessions = createSessionRepository(tx);
        // Resolve identity first so the policy can reject passwords embedding
        // the account's own email.
        const pending = await tokens.findByHash("PASSWORD_RESET", rawToken, now);
        if (pending === null) {
          return null;
        }
        const target = await users.getById(pending.userId);
        if (target === null) {
          return null;
        }
        const userId = await tokens.consume("PASSWORD_RESET", rawToken, now);
        if (userId === null) {
          return null;
        }
        await users.updatePassword(userId, newPassword, { email: target.email });
        await sessions.revokeAll(userId);
        return userId;
      });
    },
  };
}