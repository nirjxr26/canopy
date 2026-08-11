import type { Kysely, Selectable } from "kysely";
import { PENDING_VERIFICATION } from "../../shared/user-status.js";
import type { Database, UsersTable } from "../../infrastructure/db/database.js";

type UserRow = Selectable<UsersTable>;

export interface UserRecord {
  id: string;
  email: string;
  firstName: string | null;
  lastName: string | null;
  status: UsersTable["status"];
  emailVerifiedAt: Date | null;
  lockedUntil: Date | null;
  lastLoginAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface UserWithPasswordHash extends UserRecord {
  passwordHash: string;
}

export interface NewUser {
  id: string;
  email: string;
  passwordHash: string;
  firstName?: string;
  lastName?: string;
}

export type UserUpdate = Partial<{
  passwordHash: string;
  firstName: string;
  lastName: string;
  status: UsersTable["status"];
  emailVerifiedAt: Date;
  lockedUntil: Date;
  lastLoginAt: Date;
  updatedAt: Date;
}>;

export interface UserRepository {
  insert(user: NewUser): Promise<UserWithPasswordHash>;
  findByEmail(email: string, includeDeleted?: boolean): Promise<UserWithPasswordHash | null>;
  findById(id: string): Promise<UserWithPasswordHash | null>;
  update(id: string, patch: UserUpdate): Promise<boolean>;
  updateStatusIf(
    id: string,
    fromStatus: UsersTable["status"],
    toStatus: UsersTable["status"],
    extra?: { emailVerifiedAt?: Date; updatedAt?: Date },
  ): Promise<boolean>;
}

function toUserRecord(row: UserRow): UserWithPasswordHash {
  return {
    id: row.id,
    email: row.email,
    passwordHash: row.password_hash,
    firstName: row.first_name,
    lastName: row.last_name,
    status: row.status,
    emailVerifiedAt: row.email_verified_at,
    lockedUntil: row.locked_until,
    lastLoginAt: row.last_login_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function createUserRepository(db: Kysely<Database>): UserRepository {
  return {
    async insert(user) {
      const row = await db
        .insertInto("users")
        .values({
          id: user.id,
          email: user.email,
          password_hash: user.passwordHash,
          first_name: user.firstName ?? null,
          last_name: user.lastName ?? null,
          status: PENDING_VERIFICATION,
        })
        .returningAll()
        .executeTakeFirstOrThrow();
      return toUserRecord(row);
    },

    async findByEmail(email, includeDeleted = false) {
      let query = db
        .selectFrom("users")
        .selectAll()
        .where("email", "=", email);
      if (!includeDeleted) {
        query = query.where("deleted_at", "is", null);
      }
      const row = await query.executeTakeFirst();
      return row ? toUserRecord(row) : null;
    },

    async findById(id) {
      const row = await db
        .selectFrom("users")
        .selectAll()
        .where("id", "=", id)
        .where("deleted_at", "is", null)
        .executeTakeFirst();
      return row ? toUserRecord(row) : null;
    },

    async update(id, patch) {
      const rows = await db
        .updateTable("users")
        .set({
          password_hash: patch.passwordHash,
          first_name: patch.firstName,
          last_name: patch.lastName,
          status: patch.status,
          email_verified_at: patch.emailVerifiedAt,
          locked_until: patch.lockedUntil,
          last_login_at: patch.lastLoginAt,
          updated_at: patch.updatedAt ?? new Date(),
        })
        .where("id", "=", id)
        .where("deleted_at", "is", null)
        .returning("id")
        .execute();
      return rows.length > 0;
    },

    async updateStatusIf(id, fromStatus, toStatus, extra = {}) {
      const rows = await db
        .updateTable("users")
        .set({
          status: toStatus,
          email_verified_at: extra.emailVerifiedAt,
          updated_at: extra.updatedAt ?? new Date(),
        })
        .where("id", "=", id)
        .where("deleted_at", "is", null)
        .where("status", "=", fromStatus)
        .returning("id")
        .execute();
      return rows.length > 0;
    },
  };
}
