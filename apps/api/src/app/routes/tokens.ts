import { Router } from "express";
import { randomUUID } from "node:crypto";
import type { Config } from "../../infrastructure/config/config.js";
import type { RateLimiter } from "../../infrastructure/ratelimit/rate-limiter.js";
import type { SessionService } from "../../modules/session/session-service.js";
import { createRateLimit, ipKeyFn } from "../middleware/rate-limit.js";
import { createRequireSession, requireAuth } from "../middleware/require-session.js";

export interface TokensRouterDeps {
  config: Config;
  limiter: RateLimiter;
  sessions: SessionService;
}

/** POST /auth/tokens — exchange an authenticated session for a short-lived RS256 JWT */
export function createTokensRouter({ config, limiter, sessions }: TokensRouterDeps): Router {
  const router = Router();
  const requireSession = createRequireSession(sessions, config);

  router.post(
    "/",
    createRateLimit(limiter, config.rateLimits.tokens, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { user } = requireAuth(req);
      const payload = {
        sub: user.id,
        email: user.email,
        email_verified: user.emailVerifiedAt !== null,
        status: user.status,
        iss: config.jwtIssuer,
        aud: config.jwtAudience ?? config.jwtIssuer,
        jti: randomUUID(),
      };
      const jwt = await (await import("../../modules/jwt/jwt-service.js")).mintJwt(payload, config);
      res.json({ accessToken: jwt, expiresIn: config.jwtAccessTtlSeconds, tokenType: "Bearer", expiresAt: new Date(Date.now() + config.jwtAccessTtlSeconds * 1000) });
    },
  );

  return router;
}