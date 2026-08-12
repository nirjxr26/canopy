import type { Request, Response, NextFunction } from "express";
import * as jose from "jose";

export interface UserAuthContext {
  userId: string;
  email: string;
  emailVerified: boolean;
  status: string;
  expiresAt?: string;
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
}

/** Express middleware for consumer backends using session cookie introspection */
export function requireSession(options: RequireSessionOptions) {
  const cookieName = options.cookieName ?? "__Host-ap_session";

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
        status: "ACTIVE",
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
}

/** Express middleware for consumer backends validating RS256 Bearer JWTs */
export function verifyJwt(options: VerifyJwtOptions) {
  const tolerance = options.clockToleranceSeconds ?? 60;

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

      req.auth = {
        userId: (payload.sub as string) ?? "",
        email: (payload.email as string) ?? "",
        emailVerified: (payload.email_verified as boolean) ?? false,
        status: (payload.status as string) ?? "ACTIVE",
      };

      next();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Invalid access token";
      res.status(401).json({ error: { code: "UNAUTHENTICATED", message } });
    }
  };
}

export { requireSession as sessionMiddleware };