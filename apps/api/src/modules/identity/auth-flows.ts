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
import type { RegisterInput, RegisterResult } from "./user-service.js";

export interface SignupResult extends RegisterResult {
  devEmailLink: string | null;
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
}): AuthFlows {
  const { db, hasher, config, provider, keys, logger } = deps;

  return {
    async signup(input) {
      return db.transaction().execute(async (tx) => {
        const users = createUserService(createUserRepository(tx), hasher);
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
        if (user?.status !== "PENDING_VERIFICATION") {
          return { ...result, devEmailLink: null };
        }
        const token = await tokens.issue("EMAIL_VERIFICATION", user.id);
        const devEmailLink = (await emails.queue("verify-email", user.email, token)).devLink;
        return { ...result, devEmailLink };
      });
    },

    async verifyEmailToken(rawToken, now = new Date()) {
      return db.transaction().execute(async (tx) => {
        const users = createUserService(createUserRepository(tx), hasher);
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
        const users = createUserService(createUserRepository(tx), hasher);
        const tokens = createTokenService(createTokenRepository(tx));
        const sessions = createSessionRepository(tx);
        const userId = await tokens.consume("PASSWORD_RESET", rawToken, now);
        if (userId === null) {
          return null;
        }
        await users.updatePassword(userId, newPassword);
        await sessions.revokeAll(userId);
        return userId;
      });
    },
  };
}