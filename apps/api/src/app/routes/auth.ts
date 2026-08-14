import { Router } from "express";
import { AppError, ERROR_CODES } from "../../shared/app-error.js";
import type { Config } from "../../infrastructure/config/config.js";
import type { PasswordHasher } from "../../infrastructure/crypto/password.js";
import type { RateLimiter } from "../../infrastructure/ratelimit/rate-limiter.js";
import { canLogin } from "../../modules/identity/account-state-policy.js";
import type { UserService } from "../../modules/identity/user-service.js";
import type { UserRecord } from "../../modules/identity/user-repository.js";
import type { SessionService } from "../../modules/session/session-service.js";
import type { TokenService } from "../../modules/identity/token-service.js";
import type { AuthFlows } from "../../modules/identity/auth-flows.js";
import type { MfaService } from "../../modules/mfa/mfa-service.js";
import { createRateLimit, ipKeyFn } from "../middleware/rate-limit.js";
import { createRequireSession, requireAuth } from "../middleware/require-session.js";
import { sessionCookieValue } from "../middleware/cookie.js";

export interface AuthRouterDeps {
  config: Config;
  hasher: PasswordHasher;
  limiter: RateLimiter;
  sessions: SessionService;
  users: UserService;
  tokens: TokenService;
  flows: AuthFlows;
  mfa: MfaService;
}

export function toUserJson(user: UserRecord, mfaEnabled = false) {
  return {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    emailVerified: user.emailVerifiedAt !== null,
    status: user.status,
    mfaEnabled,
    lastLoginAt: user.lastLoginAt?.toISOString() ?? null,
  };
}

export function createAuthRouter({
  config,
  hasher,
  limiter,
  sessions,
  users,
  tokens,
  flows,
  mfa,
}: AuthRouterDeps): Router {
  const router = Router();
  const requireSession = createRequireSession(sessions, config);

  function sessionCookie(token: string, persistent: boolean = true) {
    return sessionCookieValue(config, token, persistent);
  }

  async function failLogin(ip: string, email: string): Promise<AppError> {
    const failed = await limiter.check(
      `${ip}:${email}`,
      config.rateLimits.loginFailed.limit,
      config.rateLimits.loginFailed.windowMs,
    );
    if (!failed.allowed) {
      return new AppError(ERROR_CODES.RATE_LIMITED, "Too many failed login attempts", failed.retryAfterMs);
    }
    return new AppError(ERROR_CODES.INVALID_CREDENTIALS, "Invalid email or password");
  }

  router.post(
    "/signup",
    createRateLimit(limiter, config.rateLimits.signup, ipKeyFn),
    async (req, res) => {
      const body = req.body ?? {};
      const result = await flows.signup({
        email: typeof body.email === "string" ? body.email : "",
        password: typeof body.password === "string" ? body.password : "",
        firstName: typeof body.firstName === "string" ? body.firstName : undefined,
        lastName: typeof body.lastName === "string" ? body.lastName : undefined,
      });
      const user = result.user!;
      res.status(201).json({
        user: toUserJson(user),
        ...(result.devEmailLink !== null ? { devEmailLink: result.devEmailLink } : {}),
      });
    },
  );

  router.post(
    "/login",
    createRateLimit(limiter, config.rateLimits.loginIp, ipKeyFn),
    async (req, res) => {
      const body = req.body ?? {};
      const email = typeof body.email === "string" ? body.email : "";
      const password = typeof body.password === "string" ? body.password : "";
      const account = await users.findByEmail(email);
      if (account === null) {
        await hasher.verify(await hasher.dummyHash(), password);
        throw await failLogin(ipKeyFn(req), email);
      }
      if (!canLogin(account).allowed) {
        await hasher.verify(await hasher.dummyHash(), password);
        throw await failLogin(ipKeyFn(req), email);
      }
const valid = await hasher.verify(account.passwordHash, password);
      if (!valid) {
        throw await failLogin(ipKeyFn(req), email);
      }
      const mfaEnabled = await mfa.isEnabled(account.id);
      const persistent = body.persistent !== false;
      if (mfaEnabled) {
        const mfaToken = await tokens.issue("MFA_PENDING", account.id, {
          mfaFailedAttempts: 0,
          persistent,
        });
        res.status(200).json({ mfaRequired: true, mfaToken });
        return;
      }
      await users.recordLogin(account.id);
      await users.rehashPasswordIfNeeded(account.id, account.passwordHash, password);
      const { token } = await sessions.createSession({
        userId: account.id,
        ipAddress: req.ip,
        userAgent: req.header("user-agent"),
      });
      res.setHeader("Set-Cookie", sessionCookie(token, persistent));
      res.status(200).json({ user: toUserJson(account, mfaEnabled) });
    },
  );

  router.post(
    "/logout",
    createRateLimit(limiter, config.rateLimits.logout, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { session, user } = requireAuth(req);
      await sessions.revoke(session.id, user.id);
      res.clearCookie("ap_session", { path: "/" });
      res.clearCookie("__Host-ap_session", { path: "/", secure: config.cookieSecure });
      res.status(204).end();
    },
  );

  router.get(
    "/me",
    createRateLimit(limiter, config.rateLimits.me, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { user } = requireAuth(req);
      res.status(200).json({ user: toUserJson(user, await mfa.isEnabled(user.id)) });
    },
  );

  router.post(
    "/change-password",
    createRateLimit(limiter, config.rateLimits.changePassword, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { session, user } = requireAuth(req);
      const body = req.body ?? {};
      const currentPassword = typeof body.currentPassword === "string" ? body.currentPassword : "";
      const newPassword = typeof body.newPassword === "string" ? body.newPassword : "";
      const account = await users.findByEmail(user.email);
      if (account === null) {
        throw new AppError(ERROR_CODES.INVALID_CREDENTIALS, "Invalid current password");
      }
      const valid = await hasher.verify(account.passwordHash, currentPassword);
      if (!valid) {
        throw new AppError(ERROR_CODES.INVALID_CREDENTIALS, "Invalid current password");
      }
      await users.updatePassword(account.id, newPassword);
      await sessions.revokeAllExcept(account.id, session.id);
      res.status(204).end();
    },
  );

  router.post(
    "/introspect",
    createRateLimit(limiter, config.rateLimits.introspect, ipKeyFn),
    async (req, res, next) => {
      try {
        const serviceKey = req.header("X-Service-Key");
        if (!config.serviceApiKey || serviceKey !== config.serviceApiKey) {
          throw new AppError(ERROR_CODES.UNAUTHENTICATED, "Invalid service key");
        }
        const body = req.body ?? {};
        const secret = typeof body.sessionSecret === "string" ? body.sessionSecret : "";
        if (!secret) {
          res.status(200).json({ valid: false });
          return;
        }
        const session = await sessions.findBySecret(secret);
        if (session === null) {
          res.status(200).json({ valid: false });
          return;
        }
        const user = await users.getById(session.userId);
        if (user === null || user.status === "DEACTIVATED" || user.status === "SUSPENDED") {
          res.status(200).json({ valid: false });
          return;
        }
        res.status(200).json({
          valid: true,
          userId: user.id,
          email: user.email,
          emailVerified: user.emailVerifiedAt !== null,
          expiresAt: session.expiresAt.toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  return router;
}
