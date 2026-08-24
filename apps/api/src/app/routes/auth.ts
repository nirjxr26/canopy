import { Router } from "express";
import type { Request } from "express";
import { createHash, timingSafeEqual } from "node:crypto";
import { AppError, ERROR_CODES } from "../../shared/app-error.js";
import type { Config } from "../../infrastructure/config/config.js";
import type { PasswordHasher } from "../../infrastructure/crypto/password.js";
import type { RateLimiter } from "../../infrastructure/ratelimit/rate-limiter.js";
import { canLogin, applyLock } from "../../modules/identity/account-state-policy.js";
import type { UserService } from "../../modules/identity/user-service.js";
import type { UserRecord } from "../../modules/identity/user-repository.js";
import { normalizeEmail } from "../../modules/identity/email-normalizer.js";
import type { SessionService } from "../../modules/session/session-service.js";
import { sessionCookieName } from "../../modules/session/session-service.js";
import type { TokenService } from "../../modules/identity/token-service.js";
import type { AuthFlows } from "../../modules/identity/auth-flows.js";
import type { EmailService } from "../../modules/email/email-service.js";
import type { MfaService } from "../../modules/mfa/mfa-service.js";
import type { SecurityEventService } from "../../modules/security-events/security-events-service.js";
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
  emails: EmailService;
  securityEvents?: SecurityEventService;
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

/** Constant-time service-key comparison (spec §8.1): hash both sides so lengths match. */
function serviceKeyMatches(presented: string | undefined, expected: string): boolean {
  if (typeof presented !== "string" || presented === "") {
    return false;
  }
  const presentedDigest = createHash("sha256").update(presented).digest();
  const expectedDigest = createHash("sha256").update(expected).digest();
  return timingSafeEqual(presentedDigest, expectedDigest);
}

export interface IntrospectRouterDeps {
  config: Config;
  limiter: RateLimiter;
  sessions: SessionService;
  users: UserService;
  securityEvents?: SecurityEventService;
}

/**
 * Mounted BEFORE the global Origin check: the service-key-gated introspect endpoint is
 * exempt from Origin enforcement (spec §8.1) — machine consumers send no Origin header.
 */
export function createIntrospectRouter({
  config,
  limiter,
  sessions,
  users,
  securityEvents,
}: IntrospectRouterDeps): Router {
  const router = Router();
  router.post(
    "/",
    createRateLimit(limiter, config.rateLimits.introspect, ipKeyFn),
    async (req, res, next) => {
      try {
      const serviceKey = req.header("X-Service-Key");
      // D2: evaluate EVERY configured key (no early exit) with constant-time
      // digests, so timing reveals neither which key nor how far off it was.
      const keyAccepted =
        config.serviceApiKeys.length > 0 &&
        config.serviceApiKeys
          .map((candidate) => serviceKeyMatches(serviceKey, candidate))
          .some(Boolean);
      if (!keyAccepted) {
        throw new AppError(ERROR_CODES.UNAUTHENTICATED, "Invalid service key");
      }
        const body = req.body ?? {};
        const secret = typeof body.sessionSecret === "string" ? body.sessionSecret : "";
        if (!secret) {
          await securityEvents?.record({
            eventType: "INTROSPECT_TOKEN_REJECTED",
            actor: "SYSTEM",
            correlationId: req.requestId,
          });
          res.status(200).json({ valid: false });
          return;
        }
        const session = await sessions.findBySecret(secret);
        if (session === null) {
          await securityEvents?.record({
            eventType: "INTROSPECT_TOKEN_REJECTED",
            actor: "SYSTEM",
            correlationId: req.requestId,
          });
          res.status(200).json({ valid: false });
          return;
        }
        const user = await users.getById(session.userId);
        if (user === null || user.status === "DEACTIVATED" || user.status === "SUSPENDED") {
          await securityEvents?.record({
            eventType: "INTROSPECT_TOKEN_REJECTED",
            userId: session.userId,
            actor: "SYSTEM",
            correlationId: req.requestId,
          });
          res.status(200).json({ valid: false });
          return;
        }
        // Successes are deliberately not recorded: at up to 600 calls/min/key they
        // would flood security_events with noise (H-23).
        res.status(200).json({
          valid: true,
          userId: user.id,
          email: user.email,
          emailVerified: user.emailVerifiedAt !== null,
          status: user.status,
          expiresAt: session.expiresAt.toISOString(),
        });
      } catch (err) {
        next(err);
      }
    },
  );
  return router;
}

/** Normalizes for limiter keys; invalid input gets a stable bucket instead of throwing. */
function normalizeEmailSafe(email: string): string {
  try {
    return normalizeEmail(email);
  } catch {
    return "invalid";
  }
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
  emails,
  securityEvents,
}: AuthRouterDeps): Router {
  const router = Router();
  const requireSession = createRequireSession(sessions, config);


  function sessionCookie(token: string, persistent: boolean = true) {
    return sessionCookieValue(config, token, persistent);
  }

  async function failLogin(req: Request, email: string, account?: UserRecord): Promise<AppError> {
    const ip = ipKeyFn(req);
    await securityEvents?.record({
      eventType: "LOGIN_FAILURE",
      userId: account?.id,
      ipAddress: ip,
      userAgent: req.header("user-agent"),
      correlationId: req.requestId,
    });
    if (account !== undefined) {
      // §6.6: the lock bucket is per (email, IP) — a single attacker IP cannot
      // lock a victim from arbitrary addresses, and casing variants share one bucket.
      const accountFailed = await limiter.check(
        `loginAccount:${normalizeEmailSafe(email)}:${ip}`,
        config.rateLimits.loginAccount.limit,
        config.rateLimits.loginAccount.windowMs,
      );
      if (!accountFailed.allowed) {
        const locked = applyLock(account, config.lockDurationMin * 60_000, new Date());
        await users.lockUntil(account.id, locked.lockedUntil!);
        // D3: notify the account owner their account was locked.
        await emails.queueSecurityAlert("account-locked", account.email);
        await securityEvents?.record({
          eventType: "ACCOUNT_LOCKED",
          userId: account.id,
          ipAddress: ip,
          userAgent: req.header("user-agent"),
          correlationId: req.requestId,
        });
        return new AppError(
          ERROR_CODES.RATE_LIMITED,
          "Account temporarily locked due to too many failed attempts",
          accountFailed.retryAfterMs,
        );
      }
    }
    const failed = await limiter.check(
      `${ip}:${normalizeEmailSafe(email)}`,
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
      // §6.1: the distinction between created/duplicate lives ONLY in the
      // security-event log — the client gets one uniform response.
      await securityEvents?.record({
        eventType:
          result.outcome === "created" ? "SIGNUP" : "DUPLICATE_SIGNUP_ATTEMPT",
        userId: result.userId,
        ipAddress: req.ip,
        userAgent: req.header("user-agent"),
        correlationId: req.requestId,
      });
      res.status(201).json({ message: "Check your inbox to verify your email." });
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
        throw await failLogin(req, email);
      }
      // §6.1/§6.2 enumeration defense: exactly ONE argon2 verification runs on
      // every path (unknown=dummy, known=real), so latency never reveals
      // whether an email exists or what state the account is in.
      const passwordValid = await hasher.verify(account.passwordHash, password);
      if (!passwordValid) {
        throw await failLogin(req, email, account);
      }
      // §6.1/R-12: account-state reasons live ONLY in the security-event log.
      // Blocked accounts get the same generic response as bad credentials,
      // at the same cost (single verify above).
      const loginDecision = canLogin(account);
      if (!loginDecision.allowed) {
        await securityEvents?.record({
          eventType: "LOGIN_BLOCKED",
          userId: account.id,
          ipAddress: ipKeyFn(req),
          userAgent: req.header("user-agent"),
          correlationId: req.requestId,
          metadata: { reason: loginDecision.blockReason },
        });
        throw await failLogin(req, email);
      }
      const mfaEnabled = await mfa.isEnabled(account.id);
      // Password-leg bookkeeping runs for every successful password verification,
      // including the MFA branch (last_login_at + argon2 param upgrades reach all users).
      await users.recordLogin(account.id);
      await users.rehashPasswordIfNeeded(account.id, account.passwordHash, password);
      const persistent = body.persistent !== false;
      if (mfaEnabled) {
        const mfaToken = await tokens.issue("MFA_PENDING", account.id, {
          mfaFailedAttempts: 0,
          persistent,
        });
        res.status(200).json({ mfaRequired: true, mfaToken });
        return;
      }
      const { token } = await sessions.createSession({
        userId: account.id,
        ipAddress: req.ip,
        userAgent: req.header("user-agent"),
      });
      await securityEvents?.record({
        eventType: "LOGIN_SUCCESS",
        userId: account.id,
        ipAddress: req.ip,
        userAgent: req.header("user-agent"),
        correlationId: req.requestId,
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
      res.clearCookie(sessionCookieName(config.cookieSecure), { path: "/", secure: config.cookieSecure });
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

  router.patch(
    "/me",
    createRateLimit(limiter, config.rateLimits.me, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { user } = requireAuth(req);
      const body = req.body ?? {};
      const patch: { firstName?: string | null; lastName?: string | null } = {};
      if (typeof body.firstName === "string") patch.firstName = body.firstName.trim().slice(0, 200) || null;
      if (typeof body.lastName === "string") patch.lastName = body.lastName.trim().slice(0, 200) || null;
      if (patch.firstName === undefined && patch.lastName === undefined) {
        throw new AppError(ERROR_CODES.VALIDATION, "Provide a name to update");
      }
      const updated = await users.updateProfile(user.id, patch);
      if (updated === null) {
        throw new AppError(ERROR_CODES.NOT_FOUND, "Account not found");
      }
      res.status(200).json({ user: toUserJson(updated, await mfa.isEnabled(user.id)) });
    },
  );

  router.post(
    "/change-password",
    createRateLimit(limiter, config.rateLimits.changePassword, ipKeyFn),
    requireSession,
    async (req, res) => {
      const { user } = requireAuth(req);
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
      await users.updatePassword(account.id, newPassword, { email: account.email });
      await sessions.revokeAll(account.id);
      // D3: notify the account owner their password changed.
      await emails.queueSecurityAlert("password-changed", account.email);
      await securityEvents?.record({
        eventType: "PASSWORD_CHANGED",
        userId: account.id,
        ipAddress: req.ip,
        userAgent: req.header("user-agent"),
        correlationId: req.requestId,
      });
      await securityEvents?.record({
        eventType: "ALL_SESSIONS_REVOKED",
        userId: account.id,
        ipAddress: req.ip,
        userAgent: req.header("user-agent"),
        correlationId: req.requestId,
      });
      const { token } = await sessions.createSession({
        userId: account.id,
        ipAddress: req.ip,
        userAgent: req.header("user-agent"),
      });
      res.setHeader("Set-Cookie", sessionCookie(token, true));
      res.status(204).end();
    },
  );

  return router;
}
