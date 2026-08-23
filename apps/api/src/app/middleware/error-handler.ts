import type { NextFunction, Request, Response } from "express";
import type pino from "pino";
import { AppError, ERROR_CODES } from "../../shared/app-error.js";

function writeError(
  res: Response,
  requestId: string,
  status: number,
  code: string,
  message: string,
): void {
  res.setHeader("X-Request-Id", requestId);
  res.status(status).json({ error: { code, message, requestId } });
}

export function notFoundHandler(req: Request, res: Response): void {
  const err = new AppError(ERROR_CODES.NOT_FOUND, "Not found");
  writeError(res, req.requestId, err.status, err.code, err.message);
}

function getErrorStatus(err: unknown): number | undefined {
  if (typeof err !== "object" || err === null || !("status" in err)) {
    return undefined;
  }
  const status = (err as { status?: unknown }).status;
  return typeof status === "number" && status >= 400 ? status : undefined;
}

export function createErrorHandler(logger?: pino.Logger) {
  return function errorHandler(
    err: unknown,
    req: Request,
    res: Response,
    next: NextFunction,
  ): void {
    // If the response already started, delegate to Express's default handler
    // instead of throwing from inside the error handler itself.
    if (res.headersSent) {
      next(err);
      return;
    }
    const requestId = req.requestId;

    if (err instanceof SyntaxError && "body" in err) {
      const validation = new AppError(ERROR_CODES.VALIDATION, "Invalid JSON body");
      writeError(res, requestId, validation.status, validation.code, validation.message);
      return;
    }

    if (err instanceof AppError) {
      if (err.status >= 500) {
        logger?.error({ requestId, code: err.code }, "application error");
      }
      if (err.code === "RATE_LIMITED" && err.retryAfterMs !== undefined) {
        res.setHeader("Retry-After", String(Math.ceil(err.retryAfterMs / 1000)));
      }
      writeError(res, requestId, err.status, err.code, err.message);
      return;
    }

    const status = getErrorStatus(err);
    if (status !== undefined) {
      const message =
        typeof (err as { message?: unknown }).message === "string"
          ? (err as { message: string }).message
          : "Request could not be processed";
      logger?.warn({ requestId, status }, "request error");
      writeError(res, requestId, status, "VALIDATION", message);
      return;
    }

    logger?.error({ requestId, err }, "unhandled error");
    writeError(res, requestId, 500, "INTERNAL", "Internal server error");
  };
}
