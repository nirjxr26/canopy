import { Router } from "express";
import { AppError, ERROR_CODES } from "../../shared/app-error.js";
import type { Config } from "../../infrastructure/config/config.js";
import type { PasswordHasher } from "../../infrastructure/crypto/password.js";
import type { RateLimiter } from "../../infrastructure/ratelimit/rate-limiter.js";
import type { UserService } from "../../modules/identity/user-service.js";
import type { SessionService } from "../../modules/session/session-service.js";
import type { TokenService } from "../../modules/identity/token-service.js";
import { canLogin } from "../../modules/identity/account-state-policy.js";

import type { MfaService } from "../../modules/mfa/mfa-service.js";
import type { SecurityEventService } from "../../modules/security-events/security-events-service.js";
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
  securityEvents?: SecurityEventService;
}

export function createMfaRouter({
  config,
  hasher,
  limiter,
  sessions,
  users,
  tokens,
  mfa,
  securityEvents,
}: MfaRouterDeps): Router {
  const router = Router();
  const requireSession = createRequireSession(sessions, config);

  router.post(
    "/enroll",
    createRateLimit(limiter, config.rateLimits.mfaEnroll, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { user } = requireAuth(req);
      // Re-enrolling replaces any prior pending secret (§4 / H-19-A).
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
      const code = typeof body.code === "string" ? body.code : "";
      const { recoveryCodes } = await mfa.confirm(user.id, code);
      await securityEvents?.record({
        eventType: "MFA_ENROLLED",
        userId: user.id,
        ipAddress: req.ip,
        userAgent: req.header("user-agent"),
        correlationId: req.requestId,
      });
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
      // Code verification + recovery burn + token claim happen atomically (H-17).
      const outcome = await mfa.completePendingLogin(pending, mfaToken, code, now);
      if (outcome.status === "invalid_code") {
        await securityEvents?.record({
          eventType: "MFA_FAILURE",
          userId: pending.userId,
          ipAddress: req.ip,
          userAgent: req.header("user-agent"),
          correlationId: req.requestId,
        });
        const fails = await tokens.incrementMfaFailures(pending.id);
        if (fails === null) {
          throw new AppError(ERROR_CODES.TOKEN_INVALID, "Session expired — sign in again");
        }
        if (fails >= config.mfaMaxFailedAttempts) {
          await tokens.markUsed(pending.id, now);
          throw new AppError(ERROR_CODES.MFA_INVALID, "Too many failed attempts — sign in again");
        }
        throw new AppError(ERROR_CODES.MFA_INVALID, "Invalid code");
      }
      const user = await users.getById(outcome.userId);
      if (user === null) {
        throw new AppError(ERROR_CODES.TOKEN_INVALID, "Session expired — sign in again");
      }
      // Re-check account state at session-mint time: the account may have been
      // suspended/locked/deactivated after login but before MFA completion.
      if (!canLogin(user).allowed) {
        throw new AppError(ERROR_CODES.TOKEN_INVALID, "Session expired — sign in again");
      }
      const { token } = await sessions.createSession({
        userId: user.id,
        ipAddress: req.ip,
        userAgent: req.header("user-agent"),
      });
      const persistent = (pending.metadata?.persistent as boolean | undefined) ?? true;
      await securityEvents?.record({
        eventType: "LOGIN_SUCCESS",
        userId: user.id,
        ipAddress: req.ip,
        userAgent: req.header("user-agent"),
        correlationId: req.requestId,
      });
      if (outcome.usedRecoveryCode) {
        await securityEvents?.record({
          eventType: "RECOVERY_CODE_USED",
          userId: user.id,
          ipAddress: req.ip,
          userAgent: req.header("user-agent"),
          correlationId: req.requestId,
        });
      }
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
      await securityEvents?.record({
        eventType: "MFA_DISABLED",
        userId: user.id,
        ipAddress: req.ip,
        userAgent: req.header("user-agent"),
        correlationId: req.requestId,
      });
      res.status(204).end();
    },
  );

  router.post(
    "/recovery-codes/regenerate",
    createRateLimit(limiter, config.rateLimits.mfaDisable, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { user } = requireAuth(req);
      const body = req.body ?? {};
      const code = typeof body.code === "string" ? body.code : "";
      const recoveryCodes = await mfa.regenerateRecoveryCodes(user.id, code);
      res.status(200).json({ recoveryCodes });
    },
  );

  return router;
}