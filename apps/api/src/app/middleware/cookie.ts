import type { Config } from "../../infrastructure/config/config.js";
import { sessionCookieName } from "../../modules/session/session-service.js";

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "strict" | "lax" | "none";
  maxAgeMs?: number;
  path?: string;
}

const DAY_MS = 24 * 60 * 60 * 1000;

export function sessionCookieValue(
  config: Pick<Config, "cookieSecure" | "sessionExpiryDays">,
  token: string,
  persistent: boolean = true,
): string {
  const name = sessionCookieName(config.cookieSecure);
  return serializeCookie(name, token, {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: "strict",
    path: "/",
    maxAgeMs: persistent ? config.sessionExpiryDays * DAY_MS : undefined,
  });
}

export function parseCookies(header: string | undefined): Map<string, string> {
  const cookies = new Map<string, string>();
  if (!header) {
    return cookies;
  }
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) {
      continue;
    }
    const name = part.slice(0, eq).trim();
    let value = part.slice(eq + 1).trim();
    if (value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    if (name !== "") {
      cookies.set(name, decodeURIComponent(value));
    }
  }
  return cookies;
}

export function serializeCookie(name: string, value: string, options: CookieOptions): string {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.path) {
    parts.push(`Path=${options.path}`);
  }
  if (options.maxAgeMs !== undefined) {
    parts.push(`Max-Age=${Math.floor(options.maxAgeMs / 1000)}`);
  }
  if (options.httpOnly) {
    parts.push("HttpOnly");
  }
  if (options.secure) {
    parts.push("Secure");
  }
  if (options.sameSite) {
    parts.push(`SameSite=${options.sameSite[0]!.toUpperCase()}${options.sameSite.slice(1)}`);
  }
  return parts.join("; ");
}
