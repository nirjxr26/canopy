import { Router } from "express";
import type { Request } from "express";
import { AppError, ERROR_CODES } from "../../shared/app-error.js";
import type { Config } from "../../infrastructure/config/config.js";
import type { RateLimiter } from "../../infrastructure/ratelimit/rate-limiter.js";
import { normalizeEmail } from "../../modules/identity/email-normalizer.js";
import type { TokenService } from "../../modules/identity/token-service.js";
import { assertPasswordPolicy } from "../../modules/identity/user-service.js";
import type { UserService } from "../../modules/identity/user-service.js";
import type { AuthFlows } from "../../modules/identity/auth-flows.js";
import type { EmailService } from "../../modules/email/email-service.js";
import type { MfaService } from "../../modules/mfa/mfa-service.js";
import type { SecurityEventService } from "../../modules/security-events/security-events-service.js";
import { createRateLimit, ipKeyFn } from "../middleware/rate-limit.js";
import { toUserJson } from "./auth.js";

export interface RecoveryRouterDeps {
  config: Config;
  limiter: RateLimiter;
  users: UserService;
  tokens: TokenService;
  emails: EmailService;
  flows: AuthFlows;
  mfa: MfaService;
  securityEvents?: SecurityEventService;
}

export function createRecoveryRouter({
  config,
  limiter,
  users,
  tokens,
  emails,
  flows,
  mfa,
  securityEvents,
}: RecoveryRouterDeps): Router {
  const router = Router();

  router.post(
    "/verify-email",
    createRateLimit(limiter, config.rateLimits.verifyEmail, ipKeyFn),
    async (req, res) => {
      const body = req.body ?? {};
      const raw = typeof body.token === "string" ? body.token : "";
      const userId = await flows.verifyEmailToken(raw);
      if (userId === null) {
        throw new AppError(ERROR_CODES.TOKEN_INVALID, "Invalid or expired verification token");
      }
      const user = await users.getById(userId);
      if (user === null) {
        throw new AppError(ERROR_CODES.TOKEN_INVALID, "Invalid or expired verification token");
      }
      await securityEvents?.record({
        eventType: "EMAIL_VERIFIED",
        userId: user.id,
        ipAddress: req.ip,
        userAgent: req.header("user-agent"),
        correlationId: req.requestId,
      });
      res.status(200).json({ user: toUserJson(user, await mfa.isEnabled(user.id)) });
    },
  );

  router.post(
    "/resend-verification",
    createRateLimit(limiter, config.rateLimits.resendVerification, emailKeyFn),
    async (req, res) => {
      const body = req.body ?? {};
      if (typeof body.email === "string" && body.email.trim() !== "") {
        const account = await users.findByEmail(body.email);
        if (account !== null && account.status === "PENDING_VERIFICATION") {
          // Renewal semantics: old links die when the new one is issued.
          await tokens.invalidateAll("EMAIL_VERIFICATION", account.id);
          const token = await tokens.issue("EMAIL_VERIFICATION", account.id);
          await emails.queue("verify-email", account.email, token);
        }
      }
      // §6.1: uniform response — never confirms whether the account exists.
      res.status(200).json({});
    },
  );

  router.post(
    "/forgot-password",
    createRateLimit(limiter, config.rateLimits.forgotPassword, emailKeyFn),
    async (req, res) => {
      const body = req.body ?? {};
      if (typeof body.email === "string" && body.email.trim() !== "") {
        const account = await users.findByEmail(body.email);
        if (account !== null && account.status === "ACTIVE") {
          await tokens.invalidateAll("PASSWORD_RESET", account.id);
          const token = await tokens.issue("PASSWORD_RESET", account.id);
          await emails.queue("password-reset", account.email, token);
          await securityEvents?.record({
            eventType: "PASSWORD_RESET_REQUESTED",
            userId: account.id,
            ipAddress: req.ip,
            userAgent: req.header("user-agent"),
            correlationId: req.requestId,
          });
        }
      }
      res.status(200).json({});
    },
  );

  router.post(
    "/reset-password",
    createRateLimit(limiter, config.rateLimits.resetPassword, ipKeyFn),
    async (req, res) => {
      const body = req.body ?? {};
      const raw = typeof body.token === "string" ? body.token : "";
      const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";
      await assertPasswordPolicy(newPassword);
      const userId = await flows.resetPassword(raw, newPassword);
      if (userId === null) {
        throw new AppError(ERROR_CODES.TOKEN_INVALID, "Invalid or expired reset token");
      }
      const user = await users.getById(userId);
      if (user === null) {
        throw new AppError(ERROR_CODES.TOKEN_INVALID, "Invalid or expired reset token");
      }
      await securityEvents?.record({
        eventType: "PASSWORD_CHANGED",
        userId: user.id,
        ipAddress: req.ip,
        userAgent: req.header("user-agent"),
        correlationId: req.requestId,
      });
      res.status(200).json({ user: toUserJson(user, await mfa.isEnabled(user.id)) });
    },
  );

  return router;
}

// §6.6: forgot/resend limits are per (email, IP). Invalid or missing emails
// share a per-IP "unmatched" bucket instead of one global bucket.
function emailKeyFn(req: Request): string {
  let emailPart = "unmatched";
  const body = req.body ?? {};
  if (typeof body.email === "string" && body.email.trim() !== "") {
    try {
      emailPart = normalizeEmail(body.email);
    } catch {
      // keep "unmatched"
    }
  }
  return `${emailPart}:${ipKeyFn(req)}`;
}
