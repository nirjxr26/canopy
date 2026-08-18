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
} as const;

export type SecurityEventType = (typeof SECURITY_EVENT_TYPES)[keyof typeof SECURITY_EVENT_TYPES];

export interface SecurityEventService {
  record(event: SecurityEventInput): Promise<void>;
}

export function createSecurityEventService(repository: SecurityEventRepository, logger?: Logger): SecurityEventService {
  return {
    async record(event) {
      try {
        await repository.insert(event);
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