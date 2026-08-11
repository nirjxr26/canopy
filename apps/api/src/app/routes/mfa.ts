import { Router } from "express";
import { AppError, ERROR_CODES } from "../../shared/app-error.js";
import type { Config } from "../../infrastructure/config/config.js";
import type { RateLimiter } from "../../infrastructure/ratelimit/rate-limiter.js";
import type { UserService } from "../../modules/identity/user-service.js";
import type { SessionService } from "../../modules/session/session-service.js";
import type { TokenService } from "../../modules/identity/token-service.js";

import type { MfaService } from "../../modules/mfa/mfa-service.js";
import { createRateLimit, ipKeyFn } from "../middleware/rate-limit.js";
import { createRequireSession, requireAuth } from "../middleware/require-session.js";
import { sessionCookieValue } from "../middleware/cookie.js";
import { toUserJson } from "./auth.js";

export interface MfaRouterDeps {
  config: Config;
  limiter: RateLimiter;
  sessions: SessionService;
  users: UserService;
  tokens: TokenService;
  mfa: MfaService;
}

export function createMfaRouter({ config, limiter, sessions, users, tokens, mfa }: MfaRouterDeps): Router {
  const router = Router();
  const requireSession = createRequireSession(sessions, config);

  router.post(
    "/enroll",
    createRateLimit(limiter, config.rateLimits.mfaEnroll, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { user } = requireAuth(req);
      const { secret, otpauthUrl } = await mfa.enroll(user);
      res.status(200).json({ secret, otpauthUrl });
    },
  );

  router.post(
    "/confirm",
    createRateLimit(limiter, config.rateLimits.mfaEnroll, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { user } = requireAuth(req);
      const body = req.body ?? {};
      const secret = typeof body.secret === "string" ? body.secret : "";
      const code = typeof body.code === "string" ? body.code : "";
      const { recoveryCodes } = await mfa.confirm(user, secret, code);
      res.status(200).json({ recoveryCodes });
    },
  );

  router.post(
    "/verify",
    createRateLimit(limiter, config.rateLimits.mfaVerify, ipKeyFn),
    async (req, res) => {
      const body = req.body ?? {};
      const mfaToken = typeof body.mfaToken === "string" ? body.mfaToken : "";
      const code = typeof body.code === "string" ? body.code : "";
      const now = new Date();
      const pending = await tokens.findByHash("MFA_PENDING", mfaToken, now);
      if (pending === null) {
        throw new AppError(ERROR_CODES.TOKEN_INVALID, "Session expired — sign in again");
      }
      const codeValid =
        (await mfa.verifyCode(pending.userId, code)) ||
        (await mfa.consumeRecoveryCode(pending.userId, code));
      if (!codeValid) {
        const fails = (pending.metadata?.mfaFailedAttempts as number | undefined) ?? 0;
        const next = fails + 1;
        if (next >= 5) {
          await tokens.markUsed(pending.id, now);
          throw new AppError(ERROR_CODES.MFA_INVALID, "Too many failed attempts — sign in again");
        }
        await tokens.updateMetadata(pending.id, { ...pending.metadata, mfaFailedAttempts: next });
        throw new AppError(ERROR_CODES.MFA_INVALID, "Invalid code");
      }
      await tokens.markUsed(pending.id, now);
      const user = await users.getById(pending.userId);
      if (user === null) {
        throw new AppError(ERROR_CODES.TOKEN_INVALID, "Session expired — sign in again");
      }
      const { token } = await sessions.createSession({
        userId: user.id,
        ipAddress: req.ip,
        userAgent: req.header("user-agent"),
      });
      const persistent = (pending.metadata?.persistent as boolean | undefined) ?? true;
      res.setHeader("Set-Cookie", sessionCookieValue(config, token, persistent));
      res.status(200).json({ user: toUserJson(user, true) });
    },
  );

  router.post(
    "/disable",
    createRateLimit(limiter, config.rateLimits.mfaDisable, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { user } = requireAuth(req);
      const body = req.body ?? {};
      const code = typeof body.code === "string" ? body.code : "";
      await mfa.disable(user.id, code);
      res.status(204).end();
    },
  );

  return router;
}