import { Router } from "express";
import { AppError, ERROR_CODES } from "../../shared/app-error.js";
import type { Config } from "../../infrastructure/config/config.js";
import type { RateLimiter } from "../../infrastructure/ratelimit/rate-limiter.js";
import type { SessionService, SessionListItem } from "../../modules/session/session-service.js";
import { createRateLimit, ipKeyFn } from "../middleware/rate-limit.js";
import { createRequireSession, requireAuth } from "../middleware/require-session.js";

function toSessionJson(session: SessionListItem) {  return {
    id: session.id,
    ipAddress: session.ipAddress,
    userAgent: session.userAgent,
    createdAt: session.createdAt.toISOString(),
    expiresAt: session.expiresAt.toISOString(),
    lastUsedAt: session.lastUsedAt.toISOString(),
    isCurrent: session.isCurrent,
  };
}

export interface SessionsRouterDeps {
  config: Config;
  limiter: RateLimiter;
  sessions: SessionService;
}

export function createSessionsRouter({ config, limiter, sessions }: SessionsRouterDeps): Router {
  const router = Router();
  const requireSession = createRequireSession(sessions, config);

  router.get(
    "/",
    createRateLimit(limiter, config.rateLimits.sessionsList, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { session, user } = requireAuth(req);
      const items = await sessions.listByUser(user.id, session.id);
      res.status(200).json({ sessions: items.filter((s) => s.revokedAt === null).map(toSessionJson) });
    },
  );

  router.delete(
    "/:id",
    createRateLimit(limiter, config.rateLimits.sessionRevoke, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { user } = requireAuth(req);
      const id = req.params.id;
      if (typeof id !== "string") {
        throw new AppError(ERROR_CODES.NOT_FOUND, "Session not found");
      }
      const revoked = await sessions.revoke(id, user.id);
      if (!revoked) {
        throw new AppError(ERROR_CODES.NOT_FOUND, "Session not found");
      }
      res.status(204).end();
    },
  );

  return router;
}

export function createSessionsAllRouter({ config, limiter, sessions }: SessionsRouterDeps): Router {
  const router = Router();
  const requireSession = createRequireSession(sessions, config);

  router.post(
    "/",
    createRateLimit(limiter, config.rateLimits.sessionsAll, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { user } = requireAuth(req);
      await sessions.revokeAll(user.id);
      res.status(204).end();
    },
  );

  return router;
}
