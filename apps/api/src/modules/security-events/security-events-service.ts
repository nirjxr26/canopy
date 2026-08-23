import type { Logger } from "pino";
import type { SecurityEventInput, SecurityEventRepository } from "./security-events-repository.js";

export const SECURITY_EVENT_TYPES = {
  SIGNUP: "SIGNUP",
  LOGIN_SUCCESS: "LOGIN_SUCCESS",
  LOGIN_FAILURE: "LOGIN_FAILURE",
  ACCOUNT_LOCKED: "ACCOUNT_LOCKED",
  EMAIL_VERIFIED: "EMAIL_VERIFIED",
  PASSWORD_RESET_REQUESTED: "PASSWORD_RESET_REQUESTED",
  PASSWORD_CHANGED: "PASSWORD_CHANGED",
  MFA_ENROLLED: "MFA_ENROLLED",
  MFA_DISABLED: "MFA_DISABLED",
  MFA_FAILURE: "MFA_FAILURE",
  RECOVERY_CODE_USED: "RECOVERY_CODE_USED",
  SESSION_REVOKED: "SESSION_REVOKED",
  ALL_SESSIONS_REVOKED: "ALL_SESSIONS_REVOKED",
  INTROSPECT_SUCCESS: "INTROSPECT_SUCCESS",
  INTROSPECT_TOKEN_REJECTED: "INTROSPECT_TOKEN_REJECTED",
  DUPLICATE_SIGNUP_ATTEMPT: "DUPLICATE_SIGNUP_ATTEMPT",
  LOGIN_BLOCKED: "LOGIN_BLOCKED",
} as const;

export type SecurityEventType = (typeof SECURITY_EVENT_TYPES)[keyof typeof SECURITY_EVENT_TYPES];

export interface SecurityEventService {
  record(event: SecurityEventInput): Promise<void>;
}

// R-27: event metadata is whitelisted so no secret can ever enter the audit
// log, regardless of what callers pass. Extend this set deliberately when a
// new non-secret field is genuinely needed.
const ALLOWED_METADATA_KEYS = new Set<string>(["reason"]);

function sanitizeMetadata(metadata: Record<string, unknown> | undefined): Record<string, unknown> {
  if (metadata === undefined) {
    return {};
  }
  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (ALLOWED_METADATA_KEYS.has(key)) {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

export function createSecurityEventService(repository: SecurityEventRepository, logger?: Logger): SecurityEventService {
  return {
    async record(event) {
      try {
        await repository.insert({ ...event, metadata: sanitizeMetadata(event.metadata) });
      } catch (err) {
        logger?.error({ err }, "security event recording failed");
      }
    },
  };
}

export function createNoopSecurityEventService(): SecurityEventService {
  return {
    async record() {},
  };
}