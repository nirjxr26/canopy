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
      // Deliberately distinct from other middlewares' req.auth so consumer apps
      // importing multiple auth stacks never get silently merged types.
      platformAuth?: UserAuthContext;
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
  if (at <= 0 || email.includes("@", at + 1) || /\s/.test(email)) {
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

function getSessionSecretFromCookie(cookieHeader: string | undefined, cookieName: string): string | undefined {
  if (!cookieHeader) {
    return undefined;
  }

  const cookies = cookieHeader.split(";").map((cookie) => cookie.trim());
  for (const cookie of cookies) {
    if (cookie.startsWith(`${cookieName}=`)) {
      return cookie.substring(cookieName.length + 1);
    }
    if (cookie.startsWith("ap_session=")) {
      return cookie.substring("ap_session=".length);
    }
  }

  return undefined;
}

function writeSessionError(res: Response, status: number, code: string, message: string): void {
  res.status(status).json({ error: { code, message } });
}

async function introspectSession(
  options: RequireSessionOptions,
  sessionSecret: string,
  requestTimeoutMs: number,
): Promise<
  | {
      valid: boolean;
      userId?: string;
      email?: string;
      emailVerified?: boolean;
      status?: string;
      expiresAt?: string;
    }
  | undefined
> {
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
    // Upstream outage (5xx): signal "unavailable" — the caller answers 503.
    if (response.status >= 500) {
      return undefined;
    }
    // Any upstream 4xx (e.g. our service key rejected) is a definitive
    // "not authenticated" answer, not an outage — surface as invalid session.
    return { valid: false };
  }

  return (await response.json()) as {
    valid: boolean;
    userId?: string;
    email?: string;
    emailVerified?: boolean;
    status?: string;
    expiresAt?: string;
  };
}

/** Express middleware for consumer backends using session cookie introspection */
export function requireSession(options: RequireSessionOptions) {
  validateApiBaseUrl(options.apiBaseUrl);
  const cookieName = options.cookieName ?? "__Host-ap_session";
  const requestTimeoutMs = options.requestTimeoutMs ?? 5000;

  return async function sessionMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const sessionSecret = getSessionSecretFromCookie(req.headers.cookie, cookieName);

      if (!sessionSecret) {
        writeSessionError(res, 401, "UNAUTHENTICATED", "Missing session cookie");
        return;
      }

      let data: Awaited<ReturnType<typeof introspectSession>>;
      try {
        data = await introspectSession(options, sessionSecret, requestTimeoutMs);
      } catch {
        // Timeout / network failure: the auth platform is unreachable — that is
        // not the same fact as "this session is invalid". Fail closed as 503.
        writeSessionError(res, 503, "SERVICE_UNAVAILABLE", "Session validation unavailable");
        return;
      }

      if (data === undefined) {
        writeSessionError(res, 503, "SERVICE_UNAVAILABLE", "Session validation unavailable");
        return;
      }

      if (!data.valid || !data.userId || !data.email) {
        writeSessionError(res, 401, "UNAUTHENTICATED", "Invalid or expired session");
        return;
      }

      req.platformAuth = {
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

const remoteJWKSByURL = new Map<string, ReturnType<typeof jose.createRemoteJWKSet>>();

function getRemoteJWKS(jwksUrl: string): ReturnType<typeof jose.createRemoteJWKSet> {
  let jwks = remoteJWKSByURL.get(jwksUrl);
  if (jwks === undefined) {
    jwks = jose.createRemoteJWKSet(new URL(jwksUrl));
    remoteJWKSByURL.set(jwksUrl, jwks);
  }
  return jwks;
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
      let protectedHeader: jose.ProtectedHeaderParameters;

      const verifyOptions = {
        issuer: options.issuer,
        audience: options.audience,
        clockTolerance: tolerance,
      } as const;

      if (options.publicKey) {
        const publicKey = await jose.importSPKI(options.publicKey, "RS256");
        const result = await jose.jwtVerify(token, publicKey, verifyOptions);
        payload = result.payload;
        protectedHeader = result.protectedHeader;
      } else if (options.jwksUrl) {
        const result = await jose.jwtVerify(token, getRemoteJWKS(options.jwksUrl), verifyOptions);
        payload = result.payload;
        protectedHeader = result.protectedHeader;
      } else {
        throw new Error("verifyJwt requires either publicKey or jwksUrl");
      }

      // §8.2: reject missing/typ-mismatched tokens — our mint side emits "at+jwt".
      if (protectedHeader.typ !== "at+jwt") {
        throw new Error("Invalid token typ");
      }

      if (!isValidClaims(payload)) {
        throw new Error("Invalid token claims");
      }

      req.platformAuth = {
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