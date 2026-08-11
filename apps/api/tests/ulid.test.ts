import { describe, expect, it } from "vitest";
import { createId, decodeTime, encodeTime, isUlid, ulid } from "../src/infrastructure/crypto/ulid.js";

describe("ulid", () => {
  it("produces 26 lowercase Crockford base32 characters", () => {
    const value = ulid();
    expect(value).toHaveLength(26);
    expect(isUlid(value)).toBe(true);
    expect(value).toMatch(/^[0-9a-hjkmnp-tv-z]{26}$/);
  });

  it("is unique across calls", () => {
    const ids = new Set(Array.from({ length: 1000 }, () => ulid()));
    expect(ids.size).toBe(1000);
  });

  it("round-trips the embedded timestamp", () => {
    const now = Date.now();
    expect(decodeTime(ulid(now))).toBe(now);
  });

  it("encodes the fixed epoch as all-zero time prefix", () => {
    expect(encodeTime(0)).toBe("0000000000");
  });

  it("clamps negative and NaN timestamps to zero", () => {
    expect(encodeTime(-1)).toBe("0000000000");
    expect(encodeTime(Number.NaN)).toBe("0000000000");
    expect(isUlid(ulid(Number.NaN))).toBe(true);
    expect(isUlid(ulid(-100))).toBe(true);
  });

  it("orders lexicographically by time", () => {
    const a = ulid(1_700_000_000_000);
    const b = ulid(1_700_000_000_001);
    expect(a < b).toBe(true);
  });

  it("rejects out-of-range timestamps", () => {
    expect(() => encodeTime(2 ** 48)).toThrow(RangeError);
  });

  it("rejects malformed values in decodeTime", () => {
    expect(() => decodeTime("short")).toThrow(RangeError);
    expect(() => decodeTime("AAAAAAAAAAAAAAAAAAAAAAAAAA")).toThrow(RangeError);
  });

  it("createId applies the prefix with an underscore", () => {
    for (const prefix of ["usr", "sess", "tok", "mfac", "rc"]) {
      const id = createId(prefix as never);
      expect(id).toMatch(new RegExp(`^${prefix}_[0-9a-hjkmnp-tv-z]{26}$`));
    }
  });
});
