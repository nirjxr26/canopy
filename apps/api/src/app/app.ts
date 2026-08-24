import express from "express";
import helmet from "helmet";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { pinoHttp } from "pino-http";
import type pino from "pino";
import type { Kysely } from "kysely";
import { randomUUID } from "node:crypto";
import type { Config, EncryptionKeyEntry } from "../infrastructure/config/config.js";
import type { PasswordHasher } from "../infrastructure/crypto/password.js";
import type { Database } from "../infrastructure/db/database.js";
import type { RateLimiter } from "../infrastructure/ratelimit/rate-limiter.js";
import type { UserService } from "../modules/identity/user-service.js";
import type { SessionService } from "../modules/session/session-service.js";
import type { TokenService } from "../modules/identity/token-service.js";
import type { EmailService, EmailProvider } from "../modules/email/email-service.js";
import type { MfaService } from "../modules/mfa/mfa-service.js";
import {
  createNoopSecurityEventService,
  type SecurityEventService,
} from "../modules/security-events/security-events-service.js";
import type { JwtSigner } from "../modules/jwt/jwt-service.js";
import { createJwtSigner } from "../modules/jwt/jwt-service.js";
import { createAuthFlows } from "../modules/identity/auth-flows.js";
import { sanitizeUrl } from "../infrastructure/logging/logger.js";
import { requestIdMiddleware } from "./middleware/request-id.js";
import { createErrorHandler, notFoundHandler } from "./middleware/error-handler.js";
import { createOriginCheck } from "./middleware/origin-check.js";
import { createRateLimit, ipKeyFn } from "./middleware/rate-limit.js";
import { createHealthRouter } from "./routes/health.js";
import { createAuthRouter, createIntrospectRouter } from "./routes/auth.js";
import { createRecoveryRouter } from "./routes/recovery.js";
import { createMfaRouter } from "./routes/mfa.js";
import { createTokensRouter } from "./routes/tokens.js";
import { createSessionsRouter, createSessionsAllRouter } from "./routes/sessions.js";

export interface AppDeps {
  config: Config;
  logger: pino.Logger;
  db: Kysely<Database>;
  hasher: PasswordHasher;
  limiter: RateLimiter;
  users: UserService;
  sessions: SessionService;
  tokens: TokenService;
  emails: EmailService;
  mfa: MfaService;
  provider: EmailProvider;
  keys: readonly EncryptionKeyEntry[];
  securityEvents?: SecurityEventService;
  jwtSigner?: JwtSigner;
}

export function createApp(deps: AppDeps): express.Express {
  const {
    config,
    logger,
    db,
    hasher,
    limiter,
    users,
    sessions,
    tokens,
    emails,
    mfa,
    provider,
    keys,
    securityEvents = createNoopSecurityEventService(),
    jwtSigner: signerDep,
  } = deps;
  const jwtSigner = signerDep ?? createJwtSigner(config);
  const app = express();
  const flows = createAuthFlows({ db, hasher, config, provider, keys, logger });

  app.disable("x-powered-by");
  if (config.trustProxy > 0) {
    app.set("trust proxy", config.trustProxy);
  }

  app.use(requestIdMiddleware);
  // §6.10: security headers on every response, including error responses.
  app.use(
    helmet({
      contentSecurityPolicy: { directives: { "default-src": ["'self'"] } },
      frameguard: { action: "deny" },
      hsts: { maxAge: 63072000, includeSubDomains: true },
      referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    }),
  );
  app.use(
    pinoHttp({
      logger,
      genReqId: (req) => (req as express.Request).requestId ?? randomUUID(),
      serializers: {
        req: (req) => ({
          id: req.id,
          method: req.method,
          url: sanitizeUrl(req.url),
          remoteAddress: req.remoteAddress,
        }),
      },
      customLogLevel: (_req, res, err) => {
        if (err !== undefined) return "error";
        if (res.statusCode >= 500) return "error";
        if (res.statusCode >= 400) return "warn";
        return "info";
      },
    }),
  );
  // After request-id/helmet/logging so HTTPS 403s carry X-Request-Id,
  // security headers, and an access-log entry.
  if (config.httpsEnforced) {
    app.use((req, res, next) => {
      if (!req.secure) {
        res.status(403).json({
          error: { code: "HTTPS_REQUIRED", message: "HTTPS is required" },
        });
        return;
      }
      next();
    });
  }
  app.use(express.json({ limit: "256kb" }));
  // Mounted before the Origin check: introspect authenticates via service key (§8.1).
  app.use(
    "/api/v1/auth/introspect",
    createIntrospectRouter({ config, limiter, sessions, users, securityEvents }),
  );
  app.use(createOriginCheck(config.allowedOrigins));

  app.use(
    "/api/v1/auth/tokens",
    createTokensRouter({ config, limiter, sessions, jwtSigner }),
  );

  /** GET /.well-known/jwks.json - public verification keys (no private material) */
  app.get(
    "/.well-known/jwks.json",
    createRateLimit(limiter, config.rateLimits.jwks, ipKeyFn),
    async (_req, res, next) => {
      try {
        res.type("json").send(await jwtSigner.buildJwks());
      } catch (err) {
        next(err);
      }
    },
  );

  app.use("/", createHealthRouter(db, limiter));
  app.use(
    "/api/v1/auth",
    createAuthRouter({ config, hasher, limiter, sessions, users, tokens, flows, mfa, emails, securityEvents }),
  );
  app.use(
    "/api/v1/auth",
    createRecoveryRouter({ config, limiter, users, tokens, emails, flows, mfa, securityEvents }),
  );
  app.use(
    "/api/v1/auth",
    createMfaRouter({ config, hasher, limiter, sessions, users, tokens, emails, mfa, securityEvents }),
  );
  app.use(
    "/api/v1/auth/sessions/revoke-all",
    createSessionsAllRouter({ config, limiter, sessions, securityEvents }),
  );
  app.use("/api/v1/auth/sessions", createSessionsRouter({ config, limiter, sessions, securityEvents }));

  // D4: production SPA serving (§9) — same-origin keeps the SameSite=Strict
  // CSRF posture. Mounted AFTER all API routes so it never shadows them.
  if (config.webDistDir !== undefined) {
    const distDir = resolve(process.cwd(), config.webDistDir);
    if (existsSync(distDir)) {
      logger.info({ distDir }, "serving SPA from webDistDir");
      app.use(express.static(distDir, { index: "index.html" }));
      // SPA fallback: any unmatched non-API GET serves index.html.
      app.use((req, res, next) => {
        if (
          req.method === "GET" &&
          !req.path.startsWith("/api") &&
          req.path !== "/healthz" &&
          !req.path.startsWith("/.well-known")
        ) {
          res.sendFile(join(distDir, "index.html"), (err) => {
            if (err) next();
          });
          return;
        }
        next();
      });
    } else {
      logger.warn({ webDistDir: config.webDistDir }, "WEB_DIST_DIR set but directory does not exist — SPA serving disabled");
    }
  }

  app.use(notFoundHandler);
  app.use(createErrorHandler(logger));
  return app;
}
