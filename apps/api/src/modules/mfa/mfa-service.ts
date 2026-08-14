import { createHash } from "node:crypto";
import type { EncryptionKeyEntry } from "../../infrastructure/config/config.js";
import { decryptSecret, encryptSecret, rotateSecretIfNeeded } from "../../infrastructure/crypto/cipher.js";
import {
  generateRecoveryCodes,
  generateSecret,
  otpauthUrl,
  verifyTotp,
} from "../../infrastructure/crypto/totp.js";
import type { DbExecutor } from "../../infrastructure/db/database.js";
import { AppError, ERROR_CODES } from "../../shared/app-error.js";
import { createTokenRepository } from "../identity/token-repository.js";
import { createTokenService } from "../identity/token-service.js";
import type { TokenService } from "../identity/token-service.js";
import { createMfaRepository } from "./mfa-repository.js";
import type { MfaRepository } from "./mfa-repository.js";

export interface MfaService {
  isEnabled(userId: string): Promise<boolean>;
  enroll(
    user: { id: string; email: string },
  ): Promise<{ challenge: string; secret: string; otpauthUrl: string }>;
  confirm(
    user: { id: string; email: string },
    challenge: string,
    code: string,
  ): Promise<{ recoveryCodes: string[] }>;
  verifyCode(userId: string, code: string): Promise<boolean>;
  disable(userId: string, code: string): Promise<void>;
  consumeRecoveryCode(userId: string, code: string): Promise<boolean>;
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function createMfaService(deps: {
  repository: MfaRepository;
  tokens: TokenService;
  db: DbExecutor;
  keys: readonly EncryptionKeyEntry[];
  issuer: string;
}): MfaService {
  const { repository, tokens, db, keys, issuer } = deps;

  async function isEnabled(userId: string): Promise<boolean> {
    return (await repository.findEnabledByUser(userId)) !== null;
  }

  async function enroll(
    user: { id: string; email: string },
  ): Promise<{ challenge: string; secret: string; otpauthUrl: string }> {
    const secret = generateSecret();
    const { encrypted, keyVersion } = encryptSecret(secret, keys);
    const challenge = await tokens.issue("MFA_ENROLL", user.id, {
      secretEncrypted: encrypted,
      keyVersion,
    });
    return { challenge, secret, otpauthUrl: otpauthUrl(secret, user.email, issuer) };
  }

  async function confirm(
    user: { id: string; email: string },
    challenge: string,
    code: string,
  ): Promise<{ recoveryCodes: string[] }> {
    if (await isEnabled(user.id)) {
      throw new AppError(ERROR_CODES.CONFLICT, "MFA is already enabled");
    }
    const pending = await tokens.findByHash("MFA_ENROLL", challenge);
    if (pending?.userId !== user.id) {
      throw new AppError(ERROR_CODES.TOKEN_INVALID, "Enrollment session expired — start over");
    }
    const secretEncrypted = pending.metadata.secretEncrypted;
    const keyVersion = pending.metadata.keyVersion;
    if (typeof secretEncrypted !== "string" || typeof keyVersion !== "number") {
      throw new AppError(ERROR_CODES.TOKEN_INVALID, "Enrollment session expired — start over");
    }
    const secret = decryptSecret(secretEncrypted, keys);
    if (!verifyTotp(secret, code)) {
      throw new AppError(ERROR_CODES.MFA_INVALID, "Invalid code");
    }
    const recoveryCodes = generateRecoveryCodes();
    await db.transaction().execute(async (tx) => {
      const repo = createMfaRepository(tx);
      await repo.insertCredential({
        userId: user.id,
        method: "totp",
        secretEncrypted,
        keyVersion,
      });
      await repo.insertRecoveryCodes(user.id, recoveryCodes.map(sha256));
      const consumedUserId = await createTokenService(createTokenRepository(tx)).consume(
        "MFA_ENROLL",
        challenge,
      );
      if (consumedUserId === null) {
        throw new AppError(ERROR_CODES.TOKEN_INVALID, "Enrollment session expired — start over");
      }
    });
    return { recoveryCodes };
  }

  async function verifyCode(userId: string, code: string): Promise<boolean> {
    const credential = await repository.findEnabledByUser(userId);
    if (credential === null) {
      return false;
    }
    const rotated = rotateSecretIfNeeded(credential.secretEncrypted, keys);
    if (rotated !== null) {
      await repository.updateSecret(userId, credential.method, {
        secretEncrypted: rotated.encrypted,
        keyVersion: rotated.keyVersion,
      });
    }
    const secret = decryptSecret(credential.secretEncrypted, keys);
    return verifyTotp(secret, code);
  }

  async function disable(userId: string, code: string): Promise<void> {
    if (!(await verifyCode(userId, code))) {
      throw new AppError(ERROR_CODES.MFA_INVALID, "Invalid code");
    }
    await db.transaction().execute(async (tx) => {
      const repo = createMfaRepository(tx);
      await repo.deleteRecoveryCodes(userId);
      await repo.deleteByUser(userId);
    });
  }

  async function consumeRecoveryCode(userId: string, code: string): Promise<boolean> {
    return repository.consumeRecoveryCode(userId, sha256(code));
  }

  return { isEnabled, enroll, confirm, verifyCode, disable, consumeRecoveryCode };
}