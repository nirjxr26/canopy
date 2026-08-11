import type { NextFunction, Request, Response } from "express";
import { AppError, ERROR_CODES } from "../../shared/app-error.js";

const STATE_CHANGING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

export function createOriginCheck(allowedOrigins: readonly string[]) {
  return function originCheck(req: Request, _res: Response, next: NextFunction): void {
    if (!STATE_CHANGING_METHODS.has(req.method)) {
      next();
      return;
    }
    const header = req.headers.origin ?? (req.headers.referer ? new URL(req.headers.referer).origin : undefined);
    if (header === undefined) {
      next();
      return;
    }
    if (!allowedOrigins.includes(header)) {
      next(new AppError(ERROR_CODES.INVALID_ORIGIN, "Request origin is not allowed"));
      return;
    }
    next();
  };
}
