import { AppError, ERROR_CODES } from "../../shared/app-error.js";
import type { UserStatus } from "../../shared/user-status.js";

export { USER_STATUSES } from "../../shared/user-status.js";
export type { UserStatus };

export type LoginBlockReason =
  | "PENDING_VERIFICATION"
  | "SUSPENDED"
  | "LOCKED"
  | "DEACTIVATED";

export interface LoginDecision {
  allowed: boolean;
  blockReason?: LoginBlockReason;
}

export interface UserState {
  status: UserStatus;
  emailVerifiedAt: Date | null;
  lockedUntil: Date | null;
}

const TRANSITIONS: Record<UserStatus, readonly UserStatus[]> = {
  PENDING_VERIFICATION: ["ACTIVE", "DEACTIVATED"],
  ACTIVE: ["SUSPENDED", "LOCKED", "DEACTIVATED"],
  SUSPENDED: ["ACTIVE", "DEACTIVATED"],
  LOCKED: ["ACTIVE", "DEACTIVATED"],
  DEACTIVATED: [],
};

export function canLogin(user: UserState, now: Date = new Date()): LoginDecision {
  if (user.status === "PENDING_VERIFICATION") {
    return { allowed: false, blockReason: "PENDING_VERIFICATION" };
  }
  if (user.status === "SUSPENDED") {
    return { allowed: false, blockReason: "SUSPENDED" };
  }
  if (user.status === "DEACTIVATED") {
    return { allowed: false, blockReason: "DEACTIVATED" };
  }
  if (user.status === "LOCKED" || (user.lockedUntil !== null && user.lockedUntil > now)) {
    return { allowed: false, blockReason: "LOCKED" };
  }
  return { allowed: true };
}

export function isLocked(user: UserState, now: Date = new Date()): boolean {
  return user.status === "LOCKED" || (user.lockedUntil !== null && user.lockedUntil > now);
}

export function applyLock(user: UserState, durationMs: number, now: Date = new Date()): UserState {
  return { ...user, lockedUntil: new Date(now.getTime() + durationMs) };
}

export function assertTransition(from: UserStatus, to: UserStatus): void {
  if (!TRANSITIONS[from].includes(to)) {
    throw new AppError(ERROR_CODES.CONFLICT, `illegal user status transition: ${from} -> ${to}`);
  }
}
