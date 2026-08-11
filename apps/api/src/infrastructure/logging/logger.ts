import pino from "pino";

export function createLogger(level: string): pino.Logger {
  return pino({
    level,
    base: undefined,
    redact: {
      paths: [
        "req.headers.cookie",
        "req.headers.authorization",
        "req.headers['x-service-key']",
        "*.password",
        "*.passwordHash",
        "*.currentPassword",
        "*.newPassword",
        "*.mfaSecret",
        "*.sessionSecret",
        "*.secret",
        "*.token",
        "*.connectionString",
        "*.databaseUrl",
        "*.url",
      ],
      censor: "[REDACTED]",
    },
  });
}

export function sanitizeUrl(rawUrl: string): string {
  try {
    const url = new URL(rawUrl, "http://internal"); //NOSONAR 
    url.search = "";
    return url.pathname;
  } catch {
    return rawUrl.split("?")[0] ?? rawUrl;
  }
}
