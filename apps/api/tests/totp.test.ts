import { describe, expect, it } from "vitest";
import {
  generateRecoveryCodes,
  generateSecret,
  otpauthUrl,
  verifyTotp,
} from "../src/infrastructure/crypto/totp.js";

const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

describe("totp", () => {
  it("matches the RFC 6238 SHA1 test vectors (6-digit truncation)", () => {
    const vectors: Array<[number, string]> = [
      [59, "287082"],
      [1111111109, "081804"],
      [1111111111, "050471"],
      [1234567890, "005924"],
      [2000000000, "279037"],
      [20000000000, "353130"],
    ];
    for (const [now, code] of vectors) {
      expect(verifyTotp(RFC_SECRET, code, 0, now)).toBe(true);
    }
  });

  it("accepts codes within the tolerance window", () => {
    expect(verifyTotp(RFC_SECRET, "287082", 1, 89)).toBe(true);
    expect(verifyTotp(RFC_SECRET, "287082", 1, 150)).toBe(false);
  });

  it("rejects wrong codes", () => {
    for (const wrong of ["000000", "111111", "222222", "999999", "123456"]) {
      expect(verifyTotp(RFC_SECRET, wrong, 1, 1234567890)).toBe(false);
    }
  });

  it("rejects empty and non-6-digit codes", () => {
    expect(verifyTotp(RFC_SECRET, "", 1, 1234567890)).toBe(false);
    expect(verifyTotp(RFC_SECRET, "12345", 1, 1234567890)).toBe(false);
    expect(verifyTotp(RFC_SECRET, "1234567", 1, 1234567890)).toBe(false);
    expect(verifyTotp(RFC_SECRET, "abcdef", 1, 1234567890)).toBe(false);
  });

  it("generates base32 secrets without padding", () => {
    const secret = generateSecret();
    expect(secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(verifyTotp(secret, "000000", 0, 59)).toBe(false);
  });

  it("builds the otpauth URL", () => {
    expect(otpauthUrl("JBSWY3DPEHPK3PXP", "user@example.com", "Acme Co")).toBe(
      "otpauth://totp/Acme%20Co:user%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme%20Co&algorithm=SHA1&digits=6&period=30",
    );
  });
});

describe("recovery codes", () => {
  it("generates 10 unique 10-char codes", () => {
    const codes = generateRecoveryCodes();
    expect(codes).toHaveLength(10);
    expect(new Set(codes).size).toBe(10);
    for (const code of codes) {
      expect(code).toMatch(/^[A-Z2-7]{10}$/);
    }
  });

  it("supports a custom count", () => {
    expect(generateRecoveryCodes(3)).toHaveLength(3);
  });
});
