import { describe, expect, it } from "vitest";
import {
  decryptSecret,
  encryptSecret,
  rotateSecretIfNeeded,
} from "../src/infrastructure/crypto/cipher.js";
import type { EncryptionKeyEntry } from "../src/infrastructure/config/config.js";

const keyV1 = Buffer.alloc(32, 1).toString("base64");
const keyV2 = Buffer.alloc(32, 2).toString("base64");

const keysV1: readonly EncryptionKeyEntry[] = [{ version: 1, key: keyV1 }];
const keysV2: readonly EncryptionKeyEntry[] = [{ version: 2, key: keyV2 }];
const keysV1V2: readonly EncryptionKeyEntry[] = [{ version: 1, key: keyV1 }, { version: 2, key: keyV2 }];

describe("cipher", () => {
  it("roundtrips encrypt/decrypt", () => {
    const { encrypted, keyVersion } = encryptSecret("JBSWY3DPEHPK3PXP", keysV1);
    expect(keyVersion).toBe(1);
    expect(decryptSecret(encrypted, keysV1)).toBe("JBSWY3DPEHPK3PXP");
  });

  it("re-encrypts with the newest key when rotated", () => {
    const { encrypted } = encryptSecret("JBSWY3DPEHPK3PXP", keysV1);
    const rotated = rotateSecretIfNeeded(encrypted, keysV1V2);
    expect(rotated).not.toBeNull();
    expect(rotated!.keyVersion).toBe(2);
    expect(encrypted.startsWith("v1:")).toBe(true);
    expect(rotated!.encrypted.startsWith("v2:")).toBe(true);
    expect(decryptSecret(rotated!.encrypted, keysV2)).toBe("JBSWY3DPEHPK3PXP");
  });

  it("does not rotate when already on the newest key", () => {
    const { encrypted } = encryptSecret("JBSWY3DPEHPK3PXP", keysV2);
    expect(rotateSecretIfNeeded(encrypted, keysV1V2)).toBeNull();
  });

  it("throws on decrypt with unknown key version", () => {
    const { encrypted } = encryptSecret("JBSWY3DPEHPK3PXP", keysV2);
    expect(() => decryptSecret(encrypted, keysV1)).toThrow("cannot decrypt MFA secret");
  });

  it("throws on malformed envelopes", () => {
    for (const malformed of ["garbage", "", "v1:only3parts", "v1:abc:def", "v1:YWFh:YWFhYWFhYWFhYWFhYQ=="]) {
      expect(() => decryptSecret(malformed, keysV1)).toThrow("cannot decrypt MFA secret");
      expect(() => rotateSecretIfNeeded(malformed, keysV1V2)).toThrow("cannot decrypt MFA secret");
    }
  });

  it("throws when no keys are configured", () => {
    expect(() => encryptSecret("JBSWY3DPEHPK3PXP", [])).toThrow("no encryption keys configured");
  });

  it("detects tampered ciphertext", () => {
    const { encrypted, keyVersion } = encryptSecret("JBSWY3DPEHPK3PXP", keysV1);
    const parts = encrypted.split(":");
    const tampered = Buffer.from(parts[3]!, "base64");
    tampered[0] = tampered[0]! ^ 0xff;
    const envelope = `${parts[0]}:${parts[1]}:${parts[2]}:${tampered.toString("base64")}`;
    expect(keyVersion).toBe(1);
    expect(() => decryptSecret(envelope, keysV1)).toThrow("cannot decrypt MFA secret");
  });
});