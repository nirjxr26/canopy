import type { Request, Response, NextFunction } from "express";
import * as jose from "jose";

export interface UserAuthContext {
  userId: string;
  email: string;
  emailVerified: boolean;
  status: string;
  expiresAt?: string;
}

export interface Logger {
  error(message: string, meta?: Record<string, unknown>): void;
}

declare global {
  namespace Express {
    interface Request {
      auth?: UserAuthContext;
    }
  }
}

export interface RequireSessionOptions {
  apiBaseUrl: string;
  serviceApiKey: string;
  cookieName?: string;
  requestTimeoutMs?: number;
  logger?: Logger;
}

const USER_STATUSES = new Set(["PENDING_VERIFICATION", "ACTIVE", "SUSPENDED", "LOCKED", "DEACTIVATED"]);

function isValidEmail(email: string): boolean {
  const at = email.indexOf("@");
  if (at <= 0 || email.indexOf("@", at + 1) !== -1 || /\s/.test(email)) {
    return false;
  }
  const rest = email.slice(at + 1);
  for (let i = 1; i <= rest.length - 2; i++) {
    if (rest[i] === ".") {
      return true;
    }
  }
  return false;
}

function validateApiBaseUrl(apiBaseUrl: string): void {
  let url: URL;
  try {
    url = new URL(apiBaseUrl);
  } catch {
    throw new Error("apiBaseUrl must use https, or http only for loopback hosts");
  }
  if (url.protocol === "https:") {
    return;
  }
  if (url.protocol === "http:") {
    const hostname = url.hostname.toLowerCase();
    if (hostname === "localhost" || hostname === "::1" || hostname === "[::1]" || hostname.startsWith("127.")) {
      return;
    }
  }
  throw new Error("apiBaseUrl must use https, or http only for loopback hosts");
}

/** Express middleware for consumer backends using session cookie introspection */
export function requireSession(options: RequireSessionOptions) {
  validateApiBaseUrl(options.apiBaseUrl);
  const cookieName = options.cookieName ?? "__Host-ap_session";
  const requestTimeoutMs = options.requestTimeoutMs ?? 5000;

  return async function sessionMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const cookieHeader = req.headers.cookie;
      let sessionSecret: string | undefined;

      if (cookieHeader) {
        const cookies = cookieHeader.split(";").map((c) => c.trim());
        for (const cookie of cookies) {
          if (cookie.startsWith(`${cookieName}=`)) {
            sessionSecret = cookie.substring(cookieName.length + 1);
            break;
          }
          if (cookie.startsWith("ap_session=")) {
            sessionSecret = cookie.substring("ap_session=".length);
          }
        }
      }

      if (!sessionSecret) {
        res.status(401).json({ error: { code: "UNAUTHENTICATED", message: "Missing session cookie" } });
        return;
      }

      const response = await fetch(`${options.apiBaseUrl}/api/v1/auth/introspect`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Service-Key": options.serviceApiKey,
        },
        body: JSON.stringify({ sessionSecret }),
        signal: AbortSignal.timeout(requestTimeoutMs),
      });

      if (!response.ok) {
        res.status(401).json({ error: { code: "UNAUTHENTICATED", message: "Session validation failed" } });
        return;
      }

      const data = (await response.json()) as {
        valid: boolean;
        userId?: string;
        email?: string;
        emailVerified?: boolean;
        status?: string;
        expiresAt?: string;
      };

      if (!data.valid || !data.userId || !data.email) {
        res.status(401).json({ error: { code: "UNAUTHENTICATED", message: "Invalid or expired session" } });
        return;
      }

      req.auth = {
        userId: data.userId,
        email: data.email,
        emailVerified: data.emailVerified ?? false,
        status: data.status ?? "ACTIVE",
        expiresAt: data.expiresAt,
      };

      next();
    } catch (err) {
      next(err);
    }
  };
}

export interface VerifyJwtOptions {
  publicKey?: string;
  jwksUrl?: string;
  issuer: string;
  audience: string;
  clockToleranceSeconds?: number;
  logger?: Logger;
}

function isValidClaims(
  payload: jose.JWTPayload,
): payload is {
  sub: string;
  email: string;
  email_verified: boolean;
  status: string;
  jti: string;
} {
  return (
    typeof payload.sub === "string" &&
    payload.sub.length > 0 &&
    typeof payload.email === "string" &&
    isValidEmail(payload.email) &&
    typeof payload.email_verified === "boolean" &&
    typeof payload.status === "string" &&
    USER_STATUSES.has(payload.status) &&
    typeof payload.jti === "string" &&
    payload.jti.length > 0
  );
}

function describeUnknown(value: unknown): unknown {
  if (typeof value === "string") {
    return value;
  }
  try {
    return JSON.stringify(value);
  } catch {
    return "[circular object]";
  }
}

function describeError(err: unknown): unknown {
  if (!(err instanceof Error)) {
    return describeUnknown(err);
  }
  const info: Record<string, unknown> = { name: err.name, message: err.message };
  if (err.cause !== undefined) {
    info.cause = describeError(err.cause);
  }
  return info;
}

/** Express middleware for consumer backends validating RS256 Bearer JWTs */
export function verifyJwt(options: VerifyJwtOptions) {
  const tolerance = options.clockToleranceSeconds ?? 60;
  const logger = options.logger;

  return async function jwtMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith("Bearer ")) {
        res.status(401).json({ error: { code: "UNAUTHENTICATED", message: "Missing Bearer token" } });
        return;
      }

      const token = authHeader.substring(7).trim();
      let payload: jose.JWTPayload;

      if (options.publicKey) {
        const publicKey = await jose.importSPKI(options.publicKey, "RS256");
        const result = await jose.jwtVerify(token, publicKey, {
          issuer: options.issuer,
          audience: options.audience,
          clockTolerance: tolerance,
        });
        payload = result.payload;
      } else if (options.jwksUrl) {
        const JWKS = jose.createRemoteJWKSet(new URL(options.jwksUrl));
        const result = await jose.jwtVerify(token, JWKS, {
          issuer: options.issuer,
          audience: options.audience,
          clockTolerance: tolerance,
        });
        payload = result.payload;
      } else {
        throw new Error("verifyJwt requires either publicKey or jwksUrl");
      }

      if (!isValidClaims(payload)) {
        throw new Error("Invalid token claims");
      }

      req.auth = {
        userId: payload.sub,
        email: payload.email,
        emailVerified: payload.email_verified,
        status: payload.status,
      };

      next();
    } catch (err) {
      logger?.error("JWT verification failed", { err: describeError(err) });
      res.status(401).json({ error: { code: "UNAUTHENTICATED", message: "Invalid access token" } });
    }
  };
}

export { requireSession as sessionMiddleware };