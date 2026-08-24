import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createCompositeBreachedPasswordChecker,
  createHibpBreachedPasswordChecker,
  createLocalBreachedPasswordChecker,
  getHibpFailOpenCount,
} from "../src/infrastructure/crypto/breached-passwords.js";

describe("breached-password layers", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("local layer flags exact hits and derivatives", async () => {
    const checker = createLocalBreachedPasswordChecker();
    await expect(checker.isBreached("password")).resolves.toBe(true);
    await expect(checker.isBreached("PASSWORD")).resolves.toBe(true);
    await expect(checker.isBreached("iloveyou123")).resolves.toBe(true); // derivative
    await expect(checker.isBreached("Correct-horse-battery-staple-1")).resolves.toBe(false);
  });

  it("hibp layer detects a breached suffix from the range response", async () => {
    // SHA-1 of "password" starts with 5BAA6 — craft a matching range payload.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        status: 200,
        text: async () => "0018A45C4D1DEF816XXXX62B4B629B0FB9:3\n5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:12\n",
      })),
    );
    const checker = createHibpBreachedPasswordChecker({ timeoutMs: 1000 });
    await expect(checker.isBreached("password")).resolves.toBe(true);
    await expect(checker.isBreached("Correct-horse-battery-staple-1")).resolves.toBe(false);
  });

  it("fails OPEN on hibp errors and counts the fail-open", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("boom");
      }),
    );
    const logger = { warn: vi.fn() };
    const before = getHibpFailOpenCount();
    const checker = createHibpBreachedPasswordChecker({ logger: logger as never, timeoutMs: 250 });
    await expect(checker.isBreached("Correct-horse-battery-staple-1")).resolves.toBe(false);
    expect(getHibpFailOpenCount()).toBe(before + 1);
    expect(logger.warn).toHaveBeenCalledTimes(1);
  });

  it("composite rejects when either layer trips and survives remote failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({ ok: false, status: 503 })),
    );
    const composite = createCompositeBreachedPasswordChecker({ logger: undefined });
    // local trip wins regardless of upstream
    await expect(composite.isBreached("password123")).resolves.toBe(true);
    // remote fails open -> not breached
    await expect(composite.isBreached("Correct-horse-battery-staple-1")).resolves.toBe(false);
  });
});
