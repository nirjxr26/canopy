export interface User {
  id: string;
  email: string;
  firstName: string | null;
  lastName: string | null;
  emailVerified: boolean;
  status: "PENDING_VERIFICATION" | "ACTIVE" | "SUSPENDED" | "LOCKED" | "DEACTIVATED";
  mfaEnabled: boolean;
  lastLoginAt: string | null;
}

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    requestId: string;
  };
}

export class ApiError extends Error {
  readonly code: string;
  readonly requestId: string;
  readonly status: number;

  constructor(status: number, body: ApiErrorBody["error"]) {
    super(body.message);
    this.name = "ApiError";
    this.code = body.code;
    this.requestId = body.requestId;
    this.status = status;
  }
}

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

export interface PasswordRequirement {
  label: string;
  met: boolean;
}

/** §6.5: length-only server policy; client mirrors for UX, server is the validator. */
export function getPasswordRequirements(password: string): PasswordRequirement[] {
  return [
    {
      label: `At least ${PASSWORD_MIN_LENGTH} characters`,
      met: password.length >= PASSWORD_MIN_LENGTH,
    },
    {
      label: `No more than ${PASSWORD_MAX_LENGTH} characters`,
      met: password.length <= PASSWORD_MAX_LENGTH,
    },
  ];
}

export function assertPasswordValid(password: string): string | null {
  const unmet = getPasswordRequirements(password)
    .filter((r) => !r.met)
    .map((r) => r.label);
  if (unmet.length > 0) {
    return `Password must meet all requirements: ${unmet.join(", ")}.`;
  }
  return null;
}

export function isEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@.]+\.[^\s@]+$/.test(value);
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  signal?: AbortSignal;
}

export async function api<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const res = await fetch(path, {
    method: options.method ?? "GET",
    headers: options.body === undefined ? undefined : { "Content-Type": "application/json" },
    credentials: "include",
    signal: options.signal ?? AbortSignal.timeout(15_000),
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });

  if (res.status === 204) {
    return undefined as T;
  }

  const payload: unknown = await res.json().catch(() => null);

  if (!res.ok) {
    const body = payload as ApiErrorBody | null;
    if (body?.error) {
      throw new ApiError(res.status, body.error);
    }
    throw new ApiError(res.status, {
      code: "UNKNOWN",
      message: `Request failed with status ${res.status}`,
      requestId: "",
    });
  }

  return payload as T;
}

export const authApi = {
  signup(input: { email: string; password: string; firstName?: string; lastName?: string }) {
    return api<{ message: string }>("/api/v1/auth/signup", {
      method: "POST",
      body: input,
    });
  },
  login(input: { email: string; password: string; persistent?: boolean }) {
    return api<{ user: User } | { mfaRequired: true; mfaToken: string }>("/api/v1/auth/login", {
      method: "POST",
      body: input,
    });
  },
  logout() {
    return api<void>("/api/v1/auth/logout", { method: "POST" });
  },
  me() {
    return api<{ user: User }>("/api/v1/auth/me");
  },
  updateProfile(input: { firstName?: string; lastName?: string }) {
    return api<{ user: User }>("/api/v1/auth/me", { method: "PATCH", body: input });
  },
  verifyEmail(token: string) {
    return api<{ user: User }>("/api/v1/auth/verify-email", { method: "POST", body: { token } });
  },
  resendVerification(email: string) {
    return api<Record<string, never>>("/api/v1/auth/resend-verification", {
      method: "POST",
      body: { email },
    });
  },
  forgotPassword(email: string) {
    return api<Record<string, never>>("/api/v1/auth/forgot-password", {
      method: "POST",
      body: { email },
    });
  },
  resetPassword(token: string, newPassword: string) {
    return api<{ user: User }>("/api/v1/auth/reset-password", {
      method: "POST",
      body: { token, newPassword },
    });
  },
  changePassword(input: { currentPassword: string; newPassword: string }) {
    return api<void>("/api/v1/auth/change-password", {
      method: "POST",
      body: input,
    });
  },
};

export interface Session {
  id: string;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: string;
  expiresAt: string;
  lastUsedAt: string;
  isCurrent: boolean;
}

export const sessionsApi = {
  list() {
    return api<{ sessions: Session[] }>("/api/v1/auth/sessions");
  },
  revoke(id: string) {
    return api<void>(`/api/v1/auth/sessions/${id}`, { method: "DELETE" });
  },
  revokeAll() {
    return api<void>("/api/v1/auth/sessions/revoke-all", { method: "POST" });
  },
};

export const mfaApi = {
  enroll() {
    return api<{ secret: string; otpauthUrl: string }>("/api/v1/auth/enroll", { method: "POST" });
  },
  confirm(input: { code: string }) {
    return api<{ recoveryCodes: string[] }>("/api/v1/auth/confirm", { method: "POST", body: input });
  },
  verify(input: { mfaToken: string; code: string }) {
    return api<{ user: User }>("/api/v1/auth/verify", { method: "POST", body: input });
  },
  disable(input: { currentPassword: string; code: string }) {
    return api<void>("/api/v1/auth/disable", { method: "POST", body: input });
  },
  regenerateRecoveryCodes(input: { code: string }) {
    return api<{ recoveryCodes: string[] }>("/api/v1/auth/recovery-codes/regenerate", {
      method: "POST",
      body: input,
    });
  },
};
