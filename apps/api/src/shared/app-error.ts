export const ERROR_CODES = {
  VALIDATION: "VALIDATION",
  INVALID_CREDENTIALS: "INVALID_CREDENTIALS",
  TOKEN_INVALID: "TOKEN_INVALID",
  RATE_LIMITED: "RATE_LIMITED",
  UNAUTHENTICATED: "UNAUTHENTICATED",
  NOT_FOUND: "NOT_FOUND",
  CONFLICT: "CONFLICT",
  MFA_INVALID: "MFA_INVALID",
  INVALID_ORIGIN: "INVALID_ORIGIN",
  HTTPS_REQUIRED: "HTTPS_REQUIRED",
  INTERNAL: "INTERNAL",
} as const;

export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

const HTTP_STATUS_BY_CODE: Record<ErrorCode, number> = {
  VALIDATION: 400,
  INVALID_CREDENTIALS: 401,
  TOKEN_INVALID: 400,
  RATE_LIMITED: 429,
  UNAUTHENTICATED: 401,
  NOT_FOUND: 404,
  CONFLICT: 409,
  MFA_INVALID: 400,
  INVALID_ORIGIN: 403,
  HTTPS_REQUIRED: 403,
  INTERNAL: 500,
};

export class AppError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly retryAfterMs?: number;

  constructor(code: ErrorCode, message: string, retryAfterMs?: number) {
    super(message);
    this.name = "AppError";
    this.code = code;
    this.status = HTTP_STATUS_BY_CODE[code];
    this.retryAfterMs = retryAfterMs;
  }
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}
