import { describe, expect, it } from "vitest";
import { normalizeEmail } from "../src/modules/identity/email-normalizer.js";
import { AppError } from "../src/shared/app-error.js";

describe("email normalizer", () => {
  it("lowercases and trims", () => {
    expect(normalizeEmail("  User@Example.COM ")).toBe("user@example.com");
  });

  it("keeps the local part case as-is if already lowercase", () => {
    expect(normalizeEmail("a.b+c@example.com")).toBe("a.b+c@example.com");
  });

  it("converts unicode domains to punycode", () => {
    expect(normalizeEmail("user@bücher.example")).toBe("user@xn--bcher-kva.example");
  });

  it("is idempotent", () => {
    const once = normalizeEmail("  USER@Example.com ");
    expect(normalizeEmail(once)).toBe(once);
  });

  it("strips a trailing dot from the domain", () => {
    expect(normalizeEmail("user@example.com.")).toBe("user@example.com");
    expect(normalizeEmail("user@example.com..")).toBe("user@example.com");
  });

  it("rejects input without @", () => {
    expect(() => normalizeEmail("not-an-email")).toThrow(AppError);
  });

  it("rejects empty local part or domain", () => {
    expect(() => normalizeEmail("@example.com")).toThrow(AppError);
    expect(() => normalizeEmail("user@")).toThrow(AppError);
  });

  it("rejects addresses over 254 characters", () => {
    expect(() => normalizeEmail(`${"a".repeat(250)}@example.com`)).toThrow(AppError);
    expect(normalizeEmail(`${"a".repeat(240)}@example.com`).length).toBeLessThanOrEqual(254);
  });
});
