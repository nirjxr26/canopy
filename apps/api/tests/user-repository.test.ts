import { beforeAll, expect, it } from "vitest";
import { migrateToLatest } from "../src/infrastructure/db/migrate.js";
import { createDb } from "../src/infrastructure/db/database.js";
import { createUserRepository } from "../src/modules/identity/user-repository.js";
import { createId } from "../src/infrastructure/crypto/ulid.js";
import { describeDb, resetTestDatabase, TEST_DATABASE_URL } from "./helpers/db.js";

describeDb("user repository", () => {
  let db: Awaited<ReturnType<typeof createDb>>["db"];

  beforeAll(async () => {
    await resetTestDatabase();
    await migrateToLatest({ databaseUrl: TEST_DATABASE_URL, dbPoolMin: 2, dbPoolMax: 10 });
    db = createDb({
      databaseUrl: TEST_DATABASE_URL,
      dbPoolMin: 1,
      dbPoolMax: 2,
    }).db;
  }, 30000);

  it("inserts and finds by email (normalized) and by id", async () => {
    const repo = createUserRepository(db);
    const email = `repo-${Date.now()}@example.com`;
    await repo.insert({
      id: createId("usr"),
      email,
      passwordHash: "$argon2id$dummy",
      firstName: "Repo",
      lastName: "Tester",
    });

    const byEmail = await repo.findByEmail(email);
    expect(byEmail).not.toBeNull();
    expect(byEmail!.email).toBe(email);
    expect(byEmail!.status).toBe("PENDING_VERIFICATION");
    expect(byEmail!.firstName).toBe("Repo");
    expect(byEmail!.passwordHash).toBe("$argon2id$dummy");

    const byId = await repo.findById(byEmail!.id);
    expect(byId!.id).toBe(byEmail!.id);
  });

  it("returns null for unknown email or id", async () => {
    const repo = createUserRepository(db);
    expect(await repo.findByEmail(`missing-${Date.now()}@example.com`)).toBeNull();
    expect(await repo.findById("usr_0123456789abcdefghjkmnpqrstvwxyz")).toBeNull();
  });

  it("rejects duplicate email inserts", async () => {
    const repo = createUserRepository(db);
    const email = `dup-${Date.now()}@example.com`;
    const user = { id: createId("usr"), email, passwordHash: "$argon2id$dummy" };
    await repo.insert(user);
    await expect(repo.insert(user)).rejects.toThrow();
  });

  it("updates fields and bumps updated_at", async () => {
    const repo = createUserRepository(db);
    const email = `upd-${Date.now()}@example.com`;
    await repo.insert({ id: createId("usr"), email, passwordHash: "$argon2id$dummy" });
    const user = (await repo.findByEmail(email))!;

    const stamp = new Date("2026-08-10T09:00:00Z");
    const updated = await repo.update(user.id, {
      status: "ACTIVE",
      emailVerifiedAt: stamp,
      lastLoginAt: stamp,
      updatedAt: stamp,
    });

    expect(updated).toBe(true);
    const reloaded = (await repo.findById(user.id))!;
    expect(reloaded.status).toBe("ACTIVE");
    expect(reloaded.emailVerifiedAt).toEqual(stamp);
    expect(reloaded.lastLoginAt).toEqual(stamp);
    expect(reloaded.updatedAt).toEqual(stamp);
  });

  it("soft-deleted users are not found", async () => {
    const repo = createUserRepository(db);
    const email = `soft-${Date.now()}@example.com`;
    await repo.insert({ id: createId("usr"), email, passwordHash: "$argon2id$dummy" });
    const user = (await repo.findByEmail(email))!;

    await db.updateTable("users").set({ deleted_at: new Date() }).where("id", "=", user.id).execute();
    expect(await repo.findByEmail(email)).toBeNull();
    expect(await repo.findById(user.id)).toBeNull();
    expect(await repo.findByEmail(email, true)).not.toBeNull();
  });

  it("update on a soft-deleted row is a no-op returning false", async () => {
    const repo = createUserRepository(db);
    const email = `deleted-upd-${Date.now()}@example.com`;
    await repo.insert({ id: createId("usr"), email, passwordHash: "$argon2id$dummy" });
    const user = (await repo.findByEmail(email))!;

    await db.updateTable("users").set({ deleted_at: new Date() }).where("id", "=", user.id).execute();
    expect(await repo.update(user.id, { lastLoginAt: new Date() })).toBe(false);
  });

  it("allows re-inserting an email once the previous row is soft-deleted", async () => {
    const repo = createUserRepository(db);
    const email = `reuse-${Date.now()}@example.com`;
    await repo.insert({ id: createId("usr"), email, passwordHash: "$argon2id$dummy" });
    const user = (await repo.findByEmail(email))!;

    await db.updateTable("users").set({ deleted_at: new Date() }).where("id", "=", user.id).execute();
    const reinserted = await repo.insert({
      id: createId("usr"),
      email,
      passwordHash: "$argon2id$dummy",
    });
    expect(reinserted.email).toBe(email);
    expect(await repo.findByEmail(email)).not.toBeNull();
  });
});
