/**
 * Single source of truth for the password policy (§6.5: length-only),
 * consumed by BOTH the API validator and the web client mirror.
 * Server-side validation remains the only authority — this package exists
 * so the two sides can never drift.
 */

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

export interface PasswordRequirement {
  label: string;
  met: boolean;
}

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

export function findUnmetRequirements(password: string): string[] {
  return getPasswordRequirements(password)
    .filter((r) => !r.met)
    .map((r) => r.label);
}
