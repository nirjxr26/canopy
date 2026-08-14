import { Router } from "express";
import { AppError, ERROR_CODES } from "../../shared/app-error.js";
import type { Config } from "../../infrastructure/config/config.js";
import type { PasswordHasher } from "../../infrastructure/crypto/password.js";
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
  hasher: PasswordHasher;
  limiter: RateLimiter;
  sessions: SessionService;
  users: UserService;
  tokens: TokenService;
  mfa: MfaService;
}

export function createMfaRouter({
  config,
  hasher,
  limiter,
  sessions,
  users,
  tokens,
  mfa,
}: MfaRouterDeps): Router {
  const router = Router();
  const requireSession = createRequireSession(sessions, config);

  router.post(
    "/enroll",
    createRateLimit(limiter, config.rateLimits.mfaEnroll, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { user } = requireAuth(req);
      const { challenge, secret, otpauthUrl } = await mfa.enroll(user);
      res.status(200).json({ challenge, secret, otpauthUrl });
    },
  );

  router.post(
    "/confirm",
    createRateLimit(limiter, config.rateLimits.mfaEnroll, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { user } = requireAuth(req);
      const body = req.body ?? {};
      const challenge = typeof body.challenge === "string" ? body.challenge : "";
      const code = typeof body.code === "string" ? body.code : "";
      const { recoveryCodes } = await mfa.confirm(user, challenge, code);
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
        const fails = await tokens.incrementMfaFailures(pending.id);
        if (fails === null) {
          throw new AppError(ERROR_CODES.TOKEN_INVALID, "Session expired — sign in again");
        }
        if (fails >= 5) {
          await tokens.markUsed(pending.id, now);
          throw new AppError(ERROR_CODES.MFA_INVALID, "Too many failed attempts — sign in again");
        }
        throw new AppError(ERROR_CODES.MFA_INVALID, "Invalid code");
      }
      const claimedUserId = await tokens.consume("MFA_PENDING", mfaToken, now);
      if (claimedUserId === null) {
        throw new AppError(ERROR_CODES.TOKEN_INVALID, "Session expired — sign in again");
      }
      const user = await users.getById(claimedUserId);
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
      const { session, user } = requireAuth(req);
      const body = req.body ?? {};
      const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
      const code = typeof body.code === "string" ? body.code : "";
      const account = await users.findByEmail(user.email);
      if (account === null) {
        throw new AppError(ERROR_CODES.INVALID_CREDENTIALS, "Invalid current password");
      }
      const valid = await hasher.verify(account.passwordHash, currentPassword);
      if (!valid) {
        throw new AppError(ERROR_CODES.INVALID_CREDENTIALS, "Invalid current password");
      }
      await mfa.disable(user.id, code);
      await sessions.revokeAllExcept(user.id, session.id);
      res.status(204).end();
    },
  );

  return router;
}