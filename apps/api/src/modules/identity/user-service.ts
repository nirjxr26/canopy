import { AppError, ERROR_CODES } from "../../shared/app-error.js";
import { createId } from "../../infrastructure/crypto/ulid.js";
import type { PasswordHasher } from "../../infrastructure/crypto/password.js";
import {
  containsEmailIdentity,
  createLocalBreachedPasswordChecker,
  type BreachedPasswordChecker,
} from "../../infrastructure/crypto/breached-passwords.js";
import { normalizeEmail } from "./email-normalizer.js";
import { assertTransition } from "./account-state-policy.js";
import type { UserRecord, UserRepository, UserUpdate, UserWithPasswordHash } from "./user-repository.js";
import {
  findUnmetRequirements,
  getPasswordRequirements as getPasswordRequirementsShared,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
} from "@auuth/password-policy";

// Re-exported so existing consumers keep their import paths; the shared
// workspace package is the single source of truth (M1).
export { PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH };

export interface PasswordPolicyContext {
  /** Account identity — passwords embedding it are rejected (NIST 800-63B). */
  email?: string;
}

export interface PasswordRequirement {
  label: string;
  met: boolean;
}

/** §6.5: length-only policy (complexity rules intentionally not used). */
export function getPasswordRequirements(password: string): PasswordRequirement[] {
  return getPasswordRequirementsShared(password);
}

export interface RegisterInput {
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
}

export interface RegisterResult {
  user: UserRecord | null;
  created: boolean;
}

export interface UserService {
  register(input: RegisterInput): Promise<RegisterResult>;
  findByEmail(email: string): Promise<UserWithPasswordHash | null>;
  getById(id: string): Promise<UserRecord | null>;
  updateProfile(id: string, input: { firstName?: string | null; lastName?: string | null }): Promise<UserRecord | null>;
  verifyEmail(id: string, now?: Date): Promise<void>;
  recordLogin(id: string, now?: Date): Promise<void>;
  updatePassword(id: string, newPassword: string, context?: PasswordPolicyContext): Promise<void>;
  lockUntil(id: string, until: Date): Promise<void>;
  rehashPasswordIfNeeded(id: string, hash: string, plain: string): Promise<void>;
}

/**
 * §6.5 policy: min/max length + breached-password blocklist + must-not-contain
 * account identity. Server-side is the single source of truth (R-9).
 */
export async function assertPasswordPolicy(
  password: string,
  context?: PasswordPolicyContext,
  breached: BreachedPasswordChecker = createLocalBreachedPasswordChecker(),
): Promise<void> {
  const unmet = findUnmetRequirements(password);
  if (unmet.length > 0) {
    throw new AppError(
      ERROR_CODES.VALIDATION,
      `Password must meet all requirements: ${unmet.join(", ")}.`,
    );
  }
  if (await breached.isBreached(password)) {
    throw new AppError(
      ERROR_CODES.VALIDATION,
      "This password appears in known data breaches — choose something more unique.",
    );
  }
  if (context?.email && containsEmailIdentity(password, context.email)) {
    throw new AppError(
      ERROR_CODES.VALIDATION,
      "Password must not contain your email address.",
    );
  }
}

async function registerUser(
  repository: UserRepository,
  hasher: PasswordHasher,
  breached: BreachedPasswordChecker,
  input: RegisterInput,
): Promise<RegisterResult> {
  let email: string;
  try {
    email = normalizeEmail(input.email);
  } catch {
    throw new AppError(ERROR_CODES.VALIDATION, "Invalid email address");
  }
  await assertPasswordPolicy(input.password, { email }, breached);
  const existing = await repository.findByEmail(email);
  if (existing !== null) {
    // §6.1 signup timing uniformity: burn one full argon2 verify so duplicate
    // signups cost the same as fresh ones — latency must not reveal existence.
    await hasher.verify(await hasher.dummyHash(), input.password);
    return { created: false, user: existing };
  }
  const passwordHash = await hasher.hash(input.password);
  const user = {
    id: createId("usr"),
    email,
    passwordHash,
    firstName: input.firstName?.trim() || undefined,
    lastName: input.lastName?.trim() || undefined,
  };
  try {
    const inserted = await repository.insert(user);
    return { created: true, user: inserted };
  } catch (err) {
    if (isUniqueViolation(err, "users_email_key")) {
      // The partial unique index only covers live rows (deleted_at IS NULL),
      // so the conflicting row is always a live duplicate.
      const winner = await repository.findByEmail(email);
      return { created: false, user: winner };
    }
    throw err;
  }
}

async function verifyUserEmail(
  repository: UserRepository,
  id: string,
  now = new Date(),
): Promise<void> {
  const user = await repository.findById(id);
  if (!user) {
    return;
  }
  if (user.status === "ACTIVE" && user.emailVerifiedAt !== null) {
    return;
  }
  assertTransition(user.status, "ACTIVE");
  const updated = await repository.updateStatusIf(id, "PENDING_VERIFICATION", "ACTIVE", {
    emailVerifiedAt: now,
    updatedAt: now,
  });
  if (!updated) {
    const fresh = await repository.findById(id);
    if (!fresh) {
      return;
    }
    if (fresh.emailVerifiedAt !== null) {
      return;
    }
    throw new AppError(ERROR_CODES.CONFLICT, "Account state changed while verifying email");
  }
}

export function createUserService(
  repository: UserRepository,
  hasher: PasswordHasher,
  breached: BreachedPasswordChecker = createLocalBreachedPasswordChecker(),
): UserService {
  return {
    register: (input) => registerUser(repository, hasher, breached, input),

    findByEmail(email) {
      return repository.findByEmail(normalizeEmail(email));
    },

    async getById(id) {
      return repository.findById(id);
    },

    async updateProfile(id, input) {
      const patch: UserUpdate = { updatedAt: new Date() };
      if (input.firstName !== undefined) patch.firstName = input.firstName;
      if (input.lastName !== undefined) patch.lastName = input.lastName;
      const updated = await repository.update(id, patch);
      if (!updated) {
        return null;
      }
      return repository.findById(id);
    },

    verifyEmail: (id, now = new Date()) => verifyUserEmail(repository, id, now),

    async recordLogin(id, now = new Date()) {
      const updated = await repository.update(id, { lastLoginAt: now, updatedAt: now });
      if (!updated) {
        throw new AppError(ERROR_CODES.NOT_FOUND, "User not found");
      }
    },

    async updatePassword(id, newPassword, context) {
      await assertPasswordPolicy(newPassword, context, breached);
      const passwordHash = await hasher.hash(newPassword);
      const updated = await repository.update(id, { passwordHash, updatedAt: new Date() });
      if (!updated) {
        throw new AppError(ERROR_CODES.NOT_FOUND, "User not found");
      }
    },

    async lockUntil(id, until) {
      const updated = await repository.update(id, { lockedUntil: until, updatedAt: new Date() });
      if (!updated) {
        throw new AppError(ERROR_CODES.NOT_FOUND, "User not found");
      }
    },

    async rehashPasswordIfNeeded(id, hash, plain) {
      const newHash = await hasher.rehashIfNeeded(hash, plain);
      if (newHash !== null) {
        await repository.update(id, { passwordHash: newHash, updatedAt: new Date() });
      }
    },
  };
}

export function isUniqueViolation(err: unknown, constraint?: string): boolean {
  if (typeof err !== "object" || err === null || !("code" in err)) {
    return false;
  }
  const candidate = err as { code?: unknown; constraint?: unknown };
  if (candidate.code !== "23505") {
    return false;
  }
  if (constraint !== undefined && candidate.constraint !== constraint) {
    return false;
  }
  return true;
}
