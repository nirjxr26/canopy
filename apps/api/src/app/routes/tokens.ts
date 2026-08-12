import { Router } from "express";
import { AppError, ERROR_CODES } from "../../shared/app-error.js";
import type { Config } from "../../infrastructure/config/config.js";
import { randomUUID } from "node:crypto";

export interface TokensRouterDeps {
  config: Config;
}

/** POST /auth/tokens — mint RS256 JWT (service-key authenticated) */
export function createTokensRouter({ config }: TokensRouterDeps): Router {
  const router = Router();

  router.post(
    "/",
    async (req, res, next) => {
      try {
        const serviceKey = req.header("X-Service-Key");
        if (serviceKey !== config.serviceApiKey) {
          throw new AppError(ERROR_CODES.UNAUTHENTICATED, "Invalid service key");
        }
        // Minimal JWT mint: payload with sub/email/status, 15-min TTL
        const payload = {
          sub: "usr_demo",
          email: "demo@test.local",
          email_verified: true,
          status: "ACTIVE",
          iss: config.jwtIssuer,
          aud: config.jwtAudience ?? config.jwtIssuer,
          jti: randomUUID(),
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + config.jwtAccessTtlSeconds,
        };
        const jwt = await (await import("../../modules/jwt/jwt-service.js")).mintJwt(payload, config);
        res.json({ accessToken: jwt, expiresIn: config.jwtAccessTtlSeconds, tokenType: "Bearer", expiresAt: new Date(Date.now() + config.jwtAccessTtlSeconds * 1000) });
      } catch (err) {
        next(err);
      }
    },
  );

  return router;
}