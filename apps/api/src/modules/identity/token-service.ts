import { createHash, randomBytes } from "node:crypto";
import { createId } from "../../infrastructure/crypto/ulid.js";
import type { PendingToken, TokenKind, TokenRepository } from "./token-repository.js";

export const TOKEN_TTL_MS: Record<TokenKind, number> = {
  EMAIL_VERIFICATION: 24 * 60 * 60 * 1000,
  PASSWORD_RESET: 30 * 60 * 1000,
  MFA_PENDING: 5 * 60 * 1000,
};

export interface TokenService {
  issue(
    kind: TokenKind,
    userId: string,
    metadata?: Record<string, unknown>,
    now?: Date,
  ): Promise<string>;
  consume(kind: TokenKind, rawToken: string, now?: Date): Promise<string | null>;
  findByHash(kind: TokenKind, rawToken: string, now?: Date): Promise<PendingToken | null>;
  markUsed(id: string, now?: Date): Promise<void>;
  updateMetadata(id: string, patch: Record<string, unknown>): Promise<boolean>;
}

export function hashToken(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function createTokenService(repository: TokenRepository): TokenService {
  return {
    async issue(kind, userId, metadata, now = new Date()) {
      const raw = randomBytes(32).toString("base64url");
      await repository.insert({
        id: createId("tok"),
        userId,
        kind,
        tokenHash: hashToken(raw),
        expiresAt: new Date(now.getTime() + TOKEN_TTL_MS[kind]),
        metadata,
      });
      return raw;
    },

    async consume(kind, rawToken, now = new Date()) {
      if (typeof rawToken !== "string" || rawToken === "") {
        return null;
      }
      return repository.consumeByHash(kind, hashToken(rawToken), now);
    },

    findByHash(kind, rawToken, now = new Date()) {
      return repository.findByHash(kind, hashToken(rawToken), now);
    },

    markUsed(id, now = new Date()) {
      return repository.markUsed(id, now);
    },

    updateMetadata(id, patch) {
      return repository.updateMetadata(id, patch);
    },
  };
}
