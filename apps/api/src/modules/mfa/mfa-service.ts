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
import type { PendingToken } from "../identity/token-repository.js";
import { createTokenService } from "../identity/token-service.js";
import { createMfaRepository } from "./mfa-repository.js";
import type { MfaRepository } from "./mfa-repository.js";

export interface MfaService {
  isEnabled(userId: string): Promise<boolean>;
  /** Starts (or restarts) enrollment — replaces any prior pending secret. */
  enroll(user: { id: string; email: string }): Promise<{ secret: string; otpauthUrl: string }>;
  /** Confirms the pending enrollment with a TOTP code and issues recovery codes. */
  confirm(userId: string, code: string): Promise<{ recoveryCodes: string[] }>;
  verifyCode(userId: string, code: string): Promise<boolean>;
  disable(userId: string, code: string): Promise<void>;
  regenerateRecoveryCodes(userId: string, code: string): Promise<string[]>;
  consumeRecoveryCode(userId: string, code: string): Promise<boolean>;
  /**
   * Verifies the code (TOTP first, then recovery code) and claims the
   * MFA_PENDING token inside ONE transaction — a lost claim race rolls back
   * the recovery-code burn instead of destroying a single-use credential.
   */
  completePendingLogin(
    pending: PendingToken,
    mfaTokenRaw: string,
    code: string,
    now?: Date,
  ): Promise<PendingLoginOutcome>;
}

export type PendingLoginOutcome =
  | { status: "ok"; userId: string; usedRecoveryCode: boolean }
  | { status: "invalid_code" };

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function createMfaService(deps: {
  repository: MfaRepository;
  db: DbExecutor;
  keys: readonly EncryptionKeyEntry[];
  issuer: string;
}): MfaService {
  const { repository, db, keys, issuer } = deps;

  async function isEnabled(userId: string): Promise<boolean> {
    return (await repository.findEnabledByUser(userId)) !== null;
  }

  async function enroll(user: { id: string; email: string }) {
    const secret = generateSecret();
    const { encrypted, keyVersion } = encryptSecret(secret, keys);
    // §4: pending enrollment lives in mfa_credentials with enabled_at = NULL.
    // Re-enrolling replaces any prior pending secret (stale challenges die here,
    // and the UNIQUE(user_id, method) constraint guarantees one row per user).
    await repository.upsertPending({
      userId: user.id,
      method: "totp",
      secretEncrypted: encrypted,
      keyVersion,
    });
    return { secret, otpauthUrl: otpauthUrl(secret, user.email, issuer) };
  }

  async function confirm(userId: string, code: string): Promise<{ recoveryCodes: string[] }> {
    if (await isEnabled(userId)) {
      throw new AppError(ERROR_CODES.CONFLICT, "MFA is already enabled");
    }
    const pending = await repository.findPendingByUser(userId);
    if (pending === null) {
      throw new AppError(ERROR_CODES.TOKEN_INVALID, "Enrollment session expired — start over");
    }
    const secret = decryptSecret(pending.secretEncrypted, keys);
    if (!verifyTotp(secret, code)) {
      throw new AppError(ERROR_CODES.MFA_INVALID, "Invalid code");
    }
    const recoveryCodes = generateRecoveryCodes();
    await db.transaction().execute(async (tx) => {
      const repo = createMfaRepository(tx);
      // Atomic flip: only one concurrent confirm can win; the loser's token
      // consumption of recovery codes rolls back with the transaction.
      const enabled = await repo.enablePending(userId, pending.method, new Date());
      if (!enabled) {
        throw new AppError(ERROR_CODES.TOKEN_INVALID, "Enrollment session expired — start over");
      }
      await repo.insertRecoveryCodes(userId, recoveryCodes.map(sha256));
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

  async function regenerateRecoveryCodes(userId: string, code: string): Promise<string[]> {
    if (!(await verifyCode(userId, code))) {
      throw new AppError(ERROR_CODES.MFA_INVALID, "Invalid code");
    }
    const recoveryCodes = generateRecoveryCodes();
    await db.transaction().execute(async (tx) => {
      const repo = createMfaRepository(tx);
      await repo.deleteRecoveryCodes(userId);
      await repo.insertRecoveryCodes(userId, recoveryCodes.map(sha256));
    });
    return recoveryCodes;
  }

  async function consumeRecoveryCode(userId: string, code: string): Promise<boolean> {
    return repository.consumeRecoveryCode(userId, sha256(code));
  }

  async function completePendingLogin(
    pending: PendingToken,
    mfaTokenRaw: string,
    code: string,
    now = new Date(),
  ): Promise<PendingLoginOutcome> {
    return db.transaction().execute(async (tx): Promise<PendingLoginOutcome> => {
      const txMfa = createMfaRepository(tx);
      const credential = await txMfa.findEnabledByUser(pending.userId);
      if (credential === null) {
        throw new AppError(ERROR_CODES.TOKEN_INVALID, "Session expired — sign in again");
      }
      const rotated = rotateSecretIfNeeded(credential.secretEncrypted, keys);
      if (rotated !== null) {
        await txMfa.updateSecret(pending.userId, credential.method, {
          secretEncrypted: rotated.encrypted,
          keyVersion: rotated.keyVersion,
        });
      }
      const secret = decryptSecret(
        rotated !== null ? rotated.encrypted : credential.secretEncrypted,
        keys,
      );
      const totpOk = verifyTotp(secret, code);
      let usedRecoveryCode = false;
      if (!totpOk) {
        usedRecoveryCode = await txMfa.consumeRecoveryCode(pending.userId, sha256(code));
        if (!usedRecoveryCode) {
          return { status: "invalid_code" };
        }
      }
      // Atomic claim in the same transaction as the recovery burn.
      const claimedUserId = await createTokenService(createTokenRepository(tx)).consume(
        "MFA_PENDING",
        mfaTokenRaw,
        now,
      );
      if (claimedUserId === null || claimedUserId !== pending.userId) {
        throw new AppError(ERROR_CODES.TOKEN_INVALID, "Session expired — sign in again");
      }
      return { status: "ok", userId: claimedUserId, usedRecoveryCode };
    });
  }

  return {
    isEnabled,
    enroll,
    confirm,
    verifyCode,
    disable,
    regenerateRecoveryCodes,
    consumeRecoveryCode,
    completePendingLogin,
  };
}