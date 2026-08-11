import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEP_SECONDS = 30;
const DIGITS = 6;
const AMBIGUOUS_RE = /[IO]/;

function base32Encode(buf: Buffer): string {
  let out = "";
  let bits = 0;
  let value = 0;
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32[(value << (5 - bits)) & 31];
  }
  return out;
}

function base32Decode(input: string): Buffer {
  const cleaned = input.toUpperCase().replace(/=+$/, "");
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of cleaned) {
    const idx = BASE32.indexOf(char);
    if (idx === -1) {
      continue;
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function totpAt(secret: string, counter: number): string {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac("sha1", base32Decode(secret)).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const binary = (hmac.readUInt32BE(offset) & 0x7fffffff) % 10 ** DIGITS;
  return binary.toString().padStart(DIGITS, "0");
}

function constantTimeEqual(a: string, b: string): boolean {
  const digestA = createHash("sha256").update(a).digest();
  const digestB = createHash("sha256").update(b).digest();
  return timingSafeEqual(digestA, digestB);
}

export function generateSecret(): string {
  return base32Encode(randomBytes(20));
}

export function otpauthUrl(secret: string, email: string, issuer: string): string {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

export function generateTotpCode(secret: string, nowSeconds: number = Math.floor(Date.now() / 1000)): string {
  return totpAt(secret, Math.floor(nowSeconds / STEP_SECONDS));
}

export function verifyTotp(
  secret: string,
  code: string,
  toleranceSteps: number = 1,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): boolean {
  if (!/^\d{6}$/.test(code)) {
    return false;
  }
  const counter = Math.floor(nowSeconds / STEP_SECONDS);
  for (let offset = -toleranceSteps; offset <= toleranceSteps; offset++) {
    if (constantTimeEqual(totpAt(secret, counter + offset), code)) {
      return true;
    }
  }
  return false;
}

export function generateRecoveryCodes(count: number = 10): string[] {
  const codes = new Set<string>();
  while (codes.size < count) {
    const candidate = base32Encode(randomBytes(7)).slice(0, 10);
    if (!AMBIGUOUS_RE.test(candidate)) {
      codes.add(candidate);
    }
  }
  return [...codes];
}
