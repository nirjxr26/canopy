import { randomBytes } from "node:crypto";

const CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz";
const ENCODING_LENGTH = 32;
const TIME_LENGTH = 10;
const RANDOM_LENGTH = 16;
const TIME_MAX = Math.pow(2, 48) - 1;

export type IdPrefix = "usr" | "sess" | "tok" | "mfac" | "rc";

export function encodeTime(ms: number): string {
  ms = Math.floor(ms);
  if (!Number.isFinite(ms) || ms < 0) {
    ms = 0;
  }
  if (ms > TIME_MAX) {
    throw new RangeError("ULID timestamp exceeds 48-bit range");
  }
  let value = ms;
  let out = "";
  for (let i = TIME_LENGTH - 1; i >= 0; i--) {
    out = CROCKFORD[value % ENCODING_LENGTH]! + out;
    value = Math.floor(value / ENCODING_LENGTH);
  }
  return out;
}

export function encodeRandom(bytes: Buffer): string {
  let out = "";
  for (let i = 0; i < RANDOM_LENGTH; i++) {
    out += CROCKFORD[bytes[i]! % ENCODING_LENGTH];
  }
  return out;
}

export function ulid(now: number = Date.now()): string {
  return encodeTime(now) + encodeRandom(randomBytes(16));
}

const ULID_RE = /^[0-9a-hjkmnp-tv-z]{26}$/;

export function isUlid(value: string): boolean {
  return ULID_RE.test(value);
}

export function decodeTime(value: string): number {
  if (!isUlid(value)) {
    throw new RangeError("Invalid ULID");
  }
  let out = 0;
  for (let i = 0; i < TIME_LENGTH; i++) {
    out = out * ENCODING_LENGTH + CROCKFORD.indexOf(value[i]!);
  }
  return out;
}

export function createId(prefix: IdPrefix, now: number = Date.now()): string {
  return `${prefix}_${ulid(now)}`;
}
