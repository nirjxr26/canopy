import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { EncryptionKeyEntry } from "../config/config.js";

export interface EncryptedSecret {
  encrypted: string;
  keyVersion: number;
}

interface ParsedEnvelope {
  version: number;
  iv: Buffer;
  tag: Buffer;
  ciphertext: Buffer;
}

function newestKey(keys: readonly EncryptionKeyEntry[]): EncryptionKeyEntry {
  if (keys.length === 0) {
    throw new Error("no encryption keys configured");
  }
  return keys.reduce((newest, entry) => (entry.version > newest.version ? entry : newest));
}

function parseEnvelope(encrypted: string): ParsedEnvelope | null {
  const parts = encrypted.split(":");
  if (parts.length !== 4) {
    return null;
  }
  const versionStr = parts[0]!.slice(1);
  if (!/^\d+$/.test(versionStr)) {
    return null;
  }
  let iv: Buffer;
  let tag: Buffer;
  let ciphertext: Buffer;
  try {
    iv = Buffer.from(parts[1]!, "base64");
    tag = Buffer.from(parts[2]!, "base64");
    ciphertext = Buffer.from(parts[3]!, "base64");
  } catch {
    return null;
  }
  if (iv.length !== 12 || tag.length !== 16) {
    return null;
  }
  return { version: Number(versionStr), iv, tag, ciphertext };
}

export function encryptSecret(value: string, keys: readonly EncryptionKeyEntry[]): EncryptedSecret {
  const key = newestKey(keys);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", Buffer.from(key.key, "base64"), iv);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    encrypted: `v${key.version}:${iv.toString("base64")}:${tag.toString("base64")}:${ciphertext.toString("base64")}`,
    keyVersion: key.version,
  };
}

export function decryptSecret(encrypted: string, keys: readonly EncryptionKeyEntry[]): string {
  const parsed = parseEnvelope(encrypted);
  if (parsed === null) {
    throw new Error("cannot decrypt MFA secret");
  }
  const keyEntry = keys.find((entry) => entry.version === parsed.version);
  if (keyEntry === undefined) {
    throw new Error("cannot decrypt MFA secret");
  }
  try {
    const decipher = createDecipheriv("aes-256-gcm", Buffer.from(keyEntry.key, "base64"), parsed.iv);
    decipher.setAuthTag(parsed.tag);
    return Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()]).toString("utf8");
  } catch {
    throw new Error("cannot decrypt MFA secret");
  }
}

export function rotateSecretIfNeeded(
  encrypted: string,
  keys: readonly EncryptionKeyEntry[],
): EncryptedSecret | null {
  if (keys.length === 0) {
    return null;
  }
  const parsed = parseEnvelope(encrypted);
  if (parsed === null) {
    throw new Error("cannot decrypt MFA secret");
  }
  const newest = newestKey(keys);
  if (parsed.version >= newest.version) {
    return null;
  }
  return encryptSecret(decryptSecret(encrypted, keys), keys);
}
