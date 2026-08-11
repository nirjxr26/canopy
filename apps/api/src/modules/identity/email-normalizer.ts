import { domainToASCII } from "node:url";
import { AppError, ERROR_CODES } from "../../shared/app-error.js";

const MAX_EMAIL_LENGTH = 254;

export function normalizeEmail(raw: string): string {
  const trimmed = raw.trim();
  const at = trimmed.lastIndexOf("@");
  if (at <= 0 || at === trimmed.length - 1) {
    throw new AppError(ERROR_CODES.VALIDATION, "invalid email: missing or misplaced @");
  }
  const local = trimmed.slice(0, at).toLowerCase();
  let domain = trimmed.slice(at + 1).trim().toLowerCase().replace(/\.+$/, "");
  try {
    domain = domainToASCII(domain);
  } catch {
    throw new AppError(ERROR_CODES.VALIDATION, "invalid email: non-convertible domain");
  }
  if (domain === "") {
    throw new AppError(ERROR_CODES.VALIDATION, "invalid email: non-convertible domain");
  }
  const normalized = `${local}@${domain}`;
  if (normalized.length > MAX_EMAIL_LENGTH) {
    throw new AppError(ERROR_CODES.VALIDATION, "invalid email: too long");
  }
  return normalized;
}
