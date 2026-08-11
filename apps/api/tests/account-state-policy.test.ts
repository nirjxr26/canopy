import { describe, expect, it } from "vitest";
import {
  applyLock,
  assertTransition,
  canLogin,
  isLocked,
} from "../src/modules/identity/account-state-policy.js";
import { AppError } from "../src/shared/app-error.js";

const baseUser = {
  status: "ACTIVE" as const,
  emailVerifiedAt: new Date("2026-01-01T00:00:00Z"),
  lockedUntil: null,
};

const now = new Date("2026-08-10T12:00:00Z");

describe("account state policy", () => {
  it("allows login for an active, unlocked user", () => {
    expect(canLogin(baseUser, now)).toEqual({ allowed: true });
  });

  it("blocks pending verification", () => {
    const decision = canLogin({ ...baseUser, status: "PENDING_VERIFICATION" }, now);
    expect(decision).toEqual({ allowed: false, blockReason: "PENDING_VERIFICATION" });
  });

  it("blocks suspended and deactivated accounts", () => {
    expect(canLogin({ ...baseUser, status: "SUSPENDED" }, now).blockReason).toBe("SUSPENDED");
    expect(canLogin({ ...baseUser, status: "DEACTIVATED" }, now).blockReason).toBe("DEACTIVATED");
  });

  it("blocks while locked_until is in the future", () => {
    const locked = applyLock(baseUser, 15 * 60 * 1000, now);
    expect(isLocked(locked, now)).toBe(true);
    expect(canLogin(locked, now).blockReason).toBe("LOCKED");
  });

  it("auto-clears a time-boxed lock after expiry", () => {
    const locked = applyLock(baseUser, 15 * 60 * 1000, now);
    const later = new Date(now.getTime() + 16 * 60 * 1000);
    expect(isLocked(locked, later)).toBe(false);
    expect(canLogin(locked, later)).toEqual({ allowed: true });
  });

  it("treats LOCKED status as an indefinite block", () => {
    const decision = canLogin({ ...baseUser, status: "LOCKED" }, now);
    expect(decision).toEqual({ allowed: false, blockReason: "LOCKED" });
  });

  it("enforces the legal transition matrix", () => {
    expect(() => assertTransition("PENDING_VERIFICATION", "ACTIVE")).not.toThrow();
    expect(() => assertTransition("ACTIVE", "SUSPENDED")).not.toThrow();
    expect(() => assertTransition("SUSPENDED", "ACTIVE")).not.toThrow();
    expect(() => assertTransition("DEACTIVATED", "ACTIVE")).toThrow(/illegal/);
    expect(() => assertTransition("PENDING_VERIFICATION", "SUSPENDED")).toThrow(/illegal/);
    expect(() => assertTransition("ACTIVE", "PENDING_VERIFICATION")).toThrow(/illegal/);
  });

  it("throws AppError CONFLICT for illegal transitions (no 500s)", () => {
    expect(() => assertTransition("DEACTIVATED", "ACTIVE")).toThrow(
      expect.objectContaining({ code: "CONFLICT" }),
    );
    expect(() => assertTransition("DEACTIVATED", "ACTIVE")).toThrowError(AppError);
  });
});
