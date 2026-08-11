export const USER_STATUSES = [
  "PENDING_VERIFICATION",
  "ACTIVE",
  "SUSPENDED",
  "LOCKED",
  "DEACTIVATED",
] as const;

export type UserStatus = (typeof USER_STATUSES)[number];

export const PENDING_VERIFICATION = "PENDING_VERIFICATION";
