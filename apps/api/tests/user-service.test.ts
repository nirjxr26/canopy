import { beforeAll, expect, it } from "vitest";
import { migrateToLatest } from "../src/infrastructure/db/migrate.js";
import { createDb } from "../src/infrastructure/db/database.js";
import { createPasswordHasher } from "../src/infrastructure/crypto/password.js";
import { createUserRepository } from "../src/modules/identity/user-repository.js";
import {
  createUserService,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
} from "../src/modules/identity/user-service.js";
import { AppError } from "../src/shared/app-error.js";
import { describeDb, resetTestDatabase, TEST_DATABASE_URL } from "./helpers/db.js";

const FAST_PARAMS = { memoryCostKiB: 64, timeCost: 1, parallelism: 1, hashLength: 32 };

describeDb("user service", () => {
  let db: Awaited<ReturnType<typeof createDb>>["db"];
  let repo: ReturnType<typeof createUserRepository>;
  let service: ReturnType<typeof createUserService>;

  beforeAll(async () => {
    await resetTestDatabase();
    await migrateToLatest({ databaseUrl: TEST_DATABASE_URL, dbPoolMin: 2, dbPoolMax: 10 });
    db = createDb({ databaseUrl: TEST_DATABASE_URL, dbPoolMin: 1, dbPoolMax: 2 }).db;
    repo = createUserRepository(db);
    service = createUserService(repo, createPasswordHasher(FAST_PARAMS));
  }, 30000);

  it("registers a user: normalized email, argon2id hash, PENDING_VERIFICATION", async () => {
    const email = `Svc-${Date.now()}@Example.com`;
    const result = await service.register({ email, password: "correct horse battery staple" });

    expect(result.created).toBe(true);
    expect(result.user!.email).toBe(email.toLowerCase());
    expect(result.user!.id).toMatch(/^usr_/);
    expect(result.user!.status).toBe("PENDING_VERIFICATION");
    expect(result.user!.emailVerifiedAt).toBeNull();

    const stored = (await repo.findByEmail(email.toLowerCase()))!;
    expect(stored.passwordHash.startsWith("$argon2id$")).toBe(true);
    expect(stored.passwordHash).not.toContain("correct horse");
  });

  it("returns created=false for a duplicate email without throwing", async () => {
    const email = `dup-${Date.now()}@example.com`;
    const first = await service.register({ email, password: "some long password here" });
    const second = await service.register({ email, password: "another long password here" });

    expect(first.created).toBe(true);
    expect(second.created).toBe(false);
    expect(second.user!.id).toBe(first.user!.id);
  });

  it("does not argon2-hash when the email already exists", async () => {
    const email = `nohash-${Date.now()}@example.com`;
    let hashCalls = 0;
    const hasher = createPasswordHasher(FAST_PARAMS);
    const countingService = createUserService(repo, {
      ...hasher,
      hash: async (plain) => {
        hashCalls++;
        return hasher.hash(plain);
      },
    });

    const first = await countingService.register({ email, password: "some long password here" });
    expect(first.created).toBe(true);
    expect(hashCalls).toBe(1);

    const second = await countingService.register({ email, password: "another long password here" });
    expect(second.created).toBe(false);
    expect(hashCalls).toBe(1);
  });

  it("allows re-registering an email after the previous account was soft-deleted", async () => {
    const email = `resurrect-${Date.now()}@example.com`;
    const first = await service.register({ email, password: "some long password here" });

    await db
      .updateTable("users")
      .set({ deleted_at: new Date() })
      .where("id", "=", first.user!.id)
      .execute();

    const second = await service.register({ email, password: "brand new long password" });
    expect(second.created).toBe(true);
    expect(second.user!.id).not.toBe(first.user!.id);
  });

  it("verifyEmail does not clobber an admin suspension", async () => {
    const email = `suspend-${Date.now()}@example.com`;
    const { user } = await service.register({ email, password: "some long password here" });

    await repo.update(user!.id, { status: "SUSPENDED" });
    await expect(service.verifyEmail(user!.id)).rejects.toMatchObject({ code: "CONFLICT" });
    expect((await repo.findById(user!.id))!.status).toBe("SUSPENDED");
  });

  it("recordLogin and updatePassword on a deleted account throw NOT_FOUND", async () => {
    const email = `ghost-${Date.now()}@example.com`;
    const { user } = await service.register({ email, password: "some long password here" });

    await db
      .updateTable("users")
      .set({ deleted_at: new Date() })
      .where("id", "=", user!.id)
      .execute();

    await expect(service.recordLogin(user!.id)).rejects.toMatchObject({ code: "NOT_FOUND" });
    await expect(service.updatePassword(user!.id, "a new long password")).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
  });

  it("rejects passwords outside the policy bounds", async () => {
    const short = `short-${Date.now()}@example.com`;
    const long = `long-${Date.now()}@example.com`;
    const longPassword = "x".repeat(PASSWORD_MAX_LENGTH + 1);

    await expect(service.register({ email: short, password: "short" })).rejects.toMatchObject({
      code: "VALIDATION",
    });
    await expect(service.register({ email: long, password: longPassword })).rejects.toBeInstanceOf(AppError);
    await expect(service.register({ email: `ok-${Date.now()}@example.com`, password: "x".repeat(PASSWORD_MIN_LENGTH) })).resolves.toMatchObject({ created: true });
  });

  it("rejects invalid email shapes with VALIDATION", async () => {
    await expect(service.register({ email: "not-an-email", password: "valid password here" })).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("verifyEmail transitions the account to ACTIVE and stamps emailVerifiedAt", async () => {
    const email = `verify-${Date.now()}@example.com`;
    const { user } = await service.register({ email, password: "some long password here" });

    await service.verifyEmail(user!.id);
    const reloaded = (await repo.findById(user!.id))!;
    expect(reloaded.status).toBe("ACTIVE");
    expect(reloaded.emailVerifiedAt).not.toBeNull();
  });

  it("recordLogin stamps last_login_at", async () => {
    const email = `login-${Date.now()}@example.com`;
    const { user } = await service.register({ email, password: "some long password here" });

    await service.recordLogin(user!.id);
    expect((await repo.findById(user!.id))!.lastLoginAt).not.toBeNull();
  });

  it("updatePassword replaces the hash so old passwords stop working", async () => {
    const email = `pw-${Date.now()}@example.com`;
    const { user } = await service.register({ email, password: "first long password" });

    await service.updatePassword(user!.id, "second long password");
    const stored = (await repo.findById(user!.id))!;
    const hasher = createPasswordHasher(FAST_PARAMS);
    expect(await hasher.verify(stored.passwordHash, "second long password")).toBe(true);
    expect(await hasher.verify(stored.passwordHash, "first long password")).toBe(false);
  });

  it("rehashPasswordIfNeeded upgrades stale hashes transparently", async () => {
    const email = `rehash-${Date.now()}@example.com`;
    const { user } = await service.register({ email, password: "some long password here" });

    const staleParams = { ...FAST_PARAMS, timeCost: 1 };
    const currentParams = { ...FAST_PARAMS, timeCost: 3 };
    const oldHasher = createPasswordHasher(staleParams);
    const currentHasher = createPasswordHasher(currentParams);

    const freshService = createUserService(repo, currentHasher);
    await repo.update(user!.id, { passwordHash: await oldHasher.hash("some long password here") });

    await freshService.rehashPasswordIfNeeded(user!.id, (await repo.findById(user!.id))!.passwordHash, "some long password here");

    const stored = (await repo.findById(user!.id))!.passwordHash;
    expect(stored).toMatch(/m=64,p=1,t=3/);
    expect(await currentHasher.verify(stored, "some long password here")).toBe(true);
  });
});
