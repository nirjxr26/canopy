import { Router } from "express";
import type { Config } from "../../infrastructure/config/config.js";
import type { RateLimiter } from "../../infrastructure/ratelimit/rate-limiter.js";
import type { SessionService } from "../../modules/session/session-service.js";
import type { JwtSigner } from "../../modules/jwt/jwt-service.js";
import { ulid } from "../../infrastructure/crypto/ulid.js";
import { createRateLimit, ipKeyFn } from "../middleware/rate-limit.js";
import { createRequireSession, requireAuth } from "../middleware/require-session.js";

export interface TokensRouterDeps {
  config: Config;
  limiter: RateLimiter;
  sessions: SessionService;
  jwtSigner: JwtSigner;
}

/** POST /auth/tokens — exchange an authenticated session for a short-lived RS256 JWT */
export function createTokensRouter({ config, limiter, sessions, jwtSigner }: TokensRouterDeps): Router {
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
        jti: ulid(),
      };
      const jwt = await jwtSigner.mintJwt(payload);
      res.json({ accessToken: jwt, expiresIn: config.jwtAccessTtlSeconds, tokenType: "Bearer", expiresAt: new Date(Date.now() + config.jwtAccessTtlSeconds * 1000) });
    },
  );

  return router;
}