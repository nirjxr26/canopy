import { createHash } from "node:crypto";
import type { EncryptionKeyEntry } from "../../infrastructure/config/config.js";
import {
  decryptSecret,
  encryptSecret,
  rotateSecretIfNeeded,
} from "../../infrastructure/crypto/cipher.js";
import {
  generateRecoveryCodes,
  generateSecret,
  otpauthUrl,
  verifyTotp,
} from "../../infrastructure/crypto/totp.js";
import { AppError, ERROR_CODES } from "../../shared/app-error.js";
import type { MfaRepository } from "./mfa-repository.js";

export interface MfaService {
  isEnabled(userId: string): Promise<boolean>;
  enroll(user: { id: string; email: string }): Promise<{ secret: string; otpauthUrl: string }>;
  confirm(
    user: { id: string; email: string },
    secret: string,
    code: string,
  ): Promise<{ recoveryCodes: string[] }>;
  verifyCode(userId: string, code: string): Promise<boolean>;
  disable(userId: string, code: string): Promise<void>;
  consumeRecoveryCode(userId: string, code: string): Promise<boolean>;
}

export function createMfaService(deps: {
  repository: MfaRepository;
  keys: readonly EncryptionKeyEntry[];
  issuer: string;
}): MfaService {
  const { repository, keys, issuer } = deps;

  function sha256(value: string): string {
    return createHash("sha256").update(value).digest("hex");
  }

  async function isEnabled(userId: string): Promise<boolean> {
    return (await repository.findEnabledByUser(userId)) !== null;
  }

  async function enroll(user: { id: string; email: string }): Promise<{ secret: string; otpauthUrl: string }> {
    const secret = generateSecret();
    return { secret, otpauthUrl: otpauthUrl(secret, user.email, issuer) };
  }

  async function confirm(
    user: { id: string; email: string },
    secret: string,
    code: string,
  ): Promise<{ recoveryCodes: string[] }> {
    if (await isEnabled(user.id)) {
      throw new AppError(ERROR_CODES.CONFLICT, "MFA is already enabled");
    }
    if (!verifyTotp(secret, code)) {
      throw new AppError(ERROR_CODES.MFA_INVALID, "Invalid code");
    }
    const { encrypted, keyVersion } = encryptSecret(secret, keys);
    await repository.insertCredential({ userId: user.id, method: "totp", secretEncrypted: encrypted, keyVersion });
    const recoveryCodes = generateRecoveryCodes();
    await repository.insertRecoveryCodes(user.id, recoveryCodes.map(sha256));
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
    await repository.deleteRecoveryCodes(userId);
    await repository.deleteByUser(userId);
  }

  async function consumeRecoveryCode(userId: string, code: string): Promise<boolean> {
    return repository.consumeRecoveryCode(userId, sha256(code));
  }

  return { isEnabled, enroll, confirm, verifyCode, disable, consumeRecoveryCode };
}
