import { AppError, ERROR_CODES } from "../../shared/app-error.js";
import { createId } from "../../infrastructure/crypto/ulid.js";
import type { PasswordHasher } from "../../infrastructure/crypto/password.js";
import { normalizeEmail } from "./email-normalizer.js";
import { assertTransition } from "./account-state-policy.js";
import type { UserRecord, UserRepository, UserWithPasswordHash } from "./user-repository.js";

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

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
  verifyEmail(id: string, now?: Date): Promise<void>;
  recordLogin(id: string, now?: Date): Promise<void>;
  updatePassword(id: string, newPassword: string): Promise<void>;
  rehashPasswordIfNeeded(id: string, hash: string, plain: string): Promise<void>;
}

export function assertPasswordPolicy(password: string): void {
  if (password.length < PASSWORD_MIN_LENGTH || password.length > PASSWORD_MAX_LENGTH) {
    throw new AppError(ERROR_CODES.VALIDATION, `Password must be ${PASSWORD_MIN_LENGTH}-${PASSWORD_MAX_LENGTH} characters`);
  }
}

export function createUserService(
  repository: UserRepository,
  hasher: PasswordHasher,
): UserService {
  return {
    async register(input) {
      let email: string;
      try {
        email = normalizeEmail(input.email);
      } catch {
        throw new AppError(ERROR_CODES.VALIDATION, "Invalid email address");
      }
      assertPasswordPolicy(input.password);
      const existing = await repository.findByEmail(email);
      if (existing !== null) {
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
          const winner = await repository.findByEmail(email, true);
          return { created: false, user: winner };
        }
        throw err;
      }
    },

    findByEmail(email) {
      return repository.findByEmail(normalizeEmail(email));
    },

    async getById(id) {
      return repository.findById(id);
    },

    async verifyEmail(id, now = new Date()) {
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
    },

    async recordLogin(id, now = new Date()) {
      const updated = await repository.update(id, { lastLoginAt: now, updatedAt: now });
      if (!updated) {
        throw new AppError(ERROR_CODES.NOT_FOUND, "User not found");
      }
    },

    async updatePassword(id, newPassword) {
      assertPasswordPolicy(newPassword);
      const passwordHash = await hasher.hash(newPassword);
      const updated = await repository.update(id, { passwordHash, updatedAt: new Date() });
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
