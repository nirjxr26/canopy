import type { NextFunction, Request, Response } from "express";
import { AppError, ERROR_CODES } from "../../shared/app-error.js";
import type { Config } from "../../infrastructure/config/config.js";
import type { AuthenticatedContext, SessionService } from "../../modules/session/session-service.js";
import { sessionCookieName } from "../../modules/session/session-service.js";
import { parseCookies } from "./cookie.js";

declare global {
  namespace Express {
    interface Request {
      auth?: AuthenticatedContext;
    }
  }
}

export function createRequireSession(sessions: SessionService, config: Pick<Config, "cookieSecure">) {
  const cookieName = sessionCookieName(config.cookieSecure);
  return async function requireSession(req: Request, _res: Response, next: NextFunction): Promise<void> {
    try {
      const token = parseCookies(req.header("cookie")).get(cookieName);
      const context = await sessions.authenticate(token);
      if (context === null) {
        throw new AppError(ERROR_CODES.UNAUTHENTICATED, "Authentication required");
      }
      req.auth = context;
      next();
    } catch (err) {
      next(err);
    }
  };
}

export function requireAuth(req: Request): AuthenticatedContext {
  if (req.auth === undefined) {
    throw new AppError(ERROR_CODES.UNAUTHENTICATED, "Authentication required");
  }
  return req.auth;
}
