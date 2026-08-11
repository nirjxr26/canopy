import { describe, expect, it } from "vitest";
import { createPasswordHasher } from "../src/infrastructure/crypto/password.js";

const FAST_PARAMS = { memoryCostKiB: 64, timeCost: 1, parallelism: 1, hashLength: 32 };
const PROD_PARAMS = { memoryCostKiB: 19456, timeCost: 2, parallelism: 1, hashLength: 32 };

describe("password hasher", () => {
  it("rejects memoryCost below 8 * parallelism", () => {
    expect(() => createPasswordHasher({ memoryCostKiB: 7, timeCost: 1, parallelism: 1, hashLength: 32 })).toThrow(RangeError);
  });

  it("hashes and verifies with argon2id encoding", async () => {
    const hasher = createPasswordHasher(FAST_PARAMS);
    const hash = await hasher.hash("correct horse battery staple");
    expect(hash.startsWith("$argon2id$")).toBe(true);
    expect(await hasher.verify(hash, "correct horse battery staple")).toBe(true);
    expect(await hasher.verify(hash, "wrong password")).toBe(false);
  });

  it("produces distinct hashes for the same password (random salt)", async () => {
    const hasher = createPasswordHasher(FAST_PARAMS);
    const [a, b] = await Promise.all([hasher.hash("same password"), hasher.hash("same password")]);
    expect(a).not.toBe(b);
  });

  it("fails closed on non-argon2id hashes", async () => {
    const hasher = createPasswordHasher(FAST_PARAMS);
    expect(await hasher.verify("$argon2i$v=19$m=64,t=1,p=1$c2FsdA$c2FsdA", "anything")).toBe(false);
    expect(await hasher.verify("not-a-hash", "anything")).toBe(false);
    expect(await hasher.verify(undefined as unknown as string, "anything")).toBe(false);
  });

  it("never throws on malformed hashes in verify", async () => {
    const hasher = createPasswordHasher(FAST_PARAMS);
    await expect(hasher.verify("$argon2id$garbage$with$no$structure", "x")).resolves.toBe(false);
  });

  it("reports needsRehash when params drift from current", async () => {
    const oldHasher = createPasswordHasher({ ...FAST_PARAMS, timeCost: 1 });
    const newHasher = createPasswordHasher({ ...FAST_PARAMS, timeCost: 3 });
    const hash = await oldHasher.hash("some password");
    expect(oldHasher.needsRehash(hash)).toBe(false);
    expect(newHasher.needsRehash(hash)).toBe(true);
  });

  it("needsRehash tolerates malformed argon2id hashes (returns true)", () => {
    const hasher = createPasswordHasher(FAST_PARAMS);
    expect(hasher.needsRehash("$argon2id$garbage$with$no$structure")).toBe(true);
    expect(hasher.needsRehash("not-a-hash")).toBe(true);
  });

  it("rehashIfNeeded upgrades a stale hash to current params", async () => {
    const oldHasher = createPasswordHasher({ ...FAST_PARAMS, timeCost: 1 });
    const newHasher = createPasswordHasher({ ...FAST_PARAMS, timeCost: 3 });
    const staleHash = await oldHasher.hash("upgrade me");
    const upgraded = await newHasher.rehashIfNeeded(staleHash, "upgrade me");
    expect(upgraded).not.toBeNull();
    expect(upgraded!).toMatch(/m=64,p=1,t=3/);
    expect(await newHasher.verify(upgraded!, "upgrade me")).toBe(true);
    expect(await newHasher.rehashIfNeeded(upgraded!, "upgrade me")).toBeNull();
  });

  it("rehashIfNeeded returns null when hash is already current", async () => {
    const hasher = createPasswordHasher(FAST_PARAMS);
    const hash = await hasher.hash("current params");
    expect(await hasher.rehashIfNeeded(hash, "current params")).toBeNull();
  });

  it("dummyHash is cached and matches current params", async () => {
    const hasher = createPasswordHasher(FAST_PARAMS);
    const first = await hasher.dummyHash();
    const second = await hasher.dummyHash();
    expect(first).toBe(second);
    expect(first.startsWith("$argon2id$")).toBe(true);
  });

  it("hashes with the production config parameters", async () => {
    const hasher = createPasswordHasher(PROD_PARAMS);
    const hash = await hasher.hash("production grade password");
    expect(hash).toMatch(/m=19456,p=1,t=2/);
    expect(await hasher.verify(hash, "production grade password")).toBe(true);
    expect(hasher.needsRehash(hash)).toBe(false);
  });
});
