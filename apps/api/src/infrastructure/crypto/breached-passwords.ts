import { createHash } from "node:crypto";
import type pino from "pino";

// §6.5 / R-9 / C-8 / D1: breached-password protection behind a pluggable interface.
//
// Two layers, checked in order (either hit = reject):
//   1. Local starter blocklist  — cheap, offline, always on.
//   2. HIBP Pwned Passwords k-anonymity API (mode=hibp) — SHA-1 prefix only
//      (5 chars) is ever transmitted; full hash/plaintext never leaves memory,
//      never logged. Fail-OPEN: timeout/error/non-200 logs a WARN with reason
//      and allows the password so an upstream blip can't take signup down.
//
// Matching follows NIST 800-63B: case-insensitive exact PLUS substring match
// for local entries >= 6 chars (derivative catching without flagging every
// password containing "pass").

export interface BreachedPasswordChecker {
  isBreached(password: string): Promise<boolean>;
}

/** Curated starter set — default layer, not the ceiling (see HIBP swap-in). */
export const STARTER_BREACHED_PASSWORDS: readonly string[] = [
  "123456", "password", "123456789", "12345678", "12345", "qwerty", "1234567890", "1234567",
  "111111", "123123", "abc123", "1234", "password1", "iloveyou", "000000", "qwerty123",
  "1q2w3e", "aa12345678", "654321", "555555", "dragon", "soccer", "baseball",
  "football", "monkey", "letmein", "696969", "shadow", "master", "666666",
  "121212", "flower", "loveme", "zaq12wsx", "password123", "superman",
  "1qaz2wsx", "sunshine", "princess", "computer", "trustno1", "hello", "freedom", "whatever",
  "qazwsx", "google", "batman", "michael", "jennifer", "hunter", "buster", "thomas", "tigger",
  "robert", "harley", "ranger", "daniel", "starwars", "112233", "asdf",
  "zxcvbnm", "asdfgh", "michelle", "jessica", "pepper", "zxcvbn",
  "131313", "pass", "maggie", "159753", "aaaaaa",
  "ginger", "joshua", "cheese", "amanda", "summer", "love", "ashley", "nicole",
  "chelsea", "biteme", "matthew", "yankees", "access", "fluffy",
  "nicholas", "lover", "jasmine", "brandy", "chocolate", "test", "test123", "passw0rd",
  "p@ssword", "p@ssw0rd", "passwort", "contrasena", "motdepasse", "senha", "haslo",
  "welcome", "welcome1", "welcome123", "admin", "admin123", "administrator", "root", "toor",
  "login", "guest", "changeme", "changed", "default",
  "secret", "secrets", "starcraft", "merlin", "falcon", "eagle", "phoenix", "warrior",
  "diamond", "nascar", "mustang", "corvette", "camaro",
  "copper", "cookie", "purple", "angels", "badboy", "canada",
  "banana", "chicken", "coffee", "money", "dollar", "million", "gold", "silver",
  "crystal", "ruby", "emerald", "sapphire", "pearl",
  "heaven", "angel", "babygirl", "sweetie", "honey", "kitty", "puppy",
  "tiger", "lion", "bear", "wolf", "rabbit", "dolphin", "shark",
  "eagle1", "raven", "penguin", "panda", "koala", "zebra", "giraffe", "elephant",
  "gorilla", "leopard", "panther", "cougar", "jaguar",
];

const LOCAL_LIST = new Set(STARTER_BREACHED_PASSWORDS.map((entry) => entry.trim().toLowerCase()));

function localListHit(password: string): boolean {
  const candidate = password.trim().toLowerCase();
  if (candidate === "") return false;
  if (LOCAL_LIST.has(candidate)) return true;
  // derivative matching only against longer roots
  for (const entry of LOCAL_LIST) {
    if (entry.length >= 6 && candidate.includes(entry)) return true;
  }
  return false;
}

export function createLocalBreachedPasswordChecker(): BreachedPasswordChecker {
  return {
    async isBreached(password) {
      return localListHit(password);
    },
  };
}

/** Rejects passwords that embed the account's own email identity (cheap NIST win). */
export function containsEmailIdentity(password: string, email: string): boolean {
  const local = email.split("@")[0] ?? "";
  const domain = (email.split("@")[1] ?? "").split(".")[0] ?? "";
  const p = password.toLowerCase();
  for (const part of [local, domain]) {
    if (part.length >= 3 && p.includes(part.toLowerCase())) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// HIBP Pwned Passwords (k-anonymity)
// ---------------------------------------------------------------------------

const HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/";
const DEFAULT_HIBP_TIMEOUT_MS = 3_000;

export interface HibpFailureMetric {
  reason: string;
  prefix: string;
}

/** Monotonic counter of fail-open lookups — exposed for metrics/export later. */
const hibpMetrics = { failOpenCount: 0 };
export function getHibpFailOpenCount(): number {
  return hibpMetrics.failOpenCount;
}

export function createHibpBreachedPasswordChecker(opts: {
  logger?: pino.Logger;
  timeoutMs?: number;
} = {}): BreachedPasswordChecker {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_HIBP_TIMEOUT_MS;

  return {
    async isBreached(password) {
      // local layer first — free and offline
      if (localListHit(password)) return true;

      // HIBP's range API specifically requires SHA-1. This is only a
      // k-anonymity lookup identifier—not password storage or authentication.
      const sha1 = createHash("sha1").update(password).digest("hex").toUpperCase(); // NOSONAR
      const prefix = sha1.slice(0, 5);
      const suffix = sha1.slice(5);

      try {
        const response = await fetch(`${HIBP_RANGE_URL}${prefix}`, {
          headers: { "Add-Padding": "true" }, // extra rows make prefix enumeration harder
          signal: AbortSignal.timeout(timeoutMs),
        });
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        const body = await response.text();
        for (const line of body.split("\n")) {
          const [lineSuffix] = line.trim().split(":");
          if (lineSuffix === suffix) return true;
        }
        return false;
      } catch (err) {
        // D1 policy: fail OPEN on timeout/error/non-200 — count + warn (prefix only).
        hibpMetrics.failOpenCount += 1;
        opts.logger?.warn(
          { prefix, reason: err instanceof Error ? err.message : String(err) },
          "hibp breached-password lookup failed open",
        );
        return false;
      }
    },
  };
}

/**
 * D1 composition: local list first (cheap/offline), then HIBP (fail-open).
 * Either hit rejects.
 */
export function createCompositeBreachedPasswordChecker(opts: {
  logger?: pino.Logger;
  timeoutMs?: number;
}): BreachedPasswordChecker {
  const local = createLocalBreachedPasswordChecker();
  const remote = createHibpBreachedPasswordChecker(opts);
  return {
    async isBreached(password) {
      if (await local.isBreached(password)) return true;
      return remote.isBreached(password);
    },
  };
}
