// Serves the API against auuth_test with permissive rate limits so schemathesis
// can fuzz without tripping limiters. Replaces the old cmd `set "VAR=..."` script,
// which truncated RATE_LIMITS_JSON at the first nested double quote on Windows.
import { spawn } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
// Invoke tsx's CLI directly (no npx/shell) so this behaves identically cross-platform.
const tsxCli = require.resolve("tsx/cli");

const LIMIT_NAMES = [
  "signup",
  "loginIp",
  "loginFailed",
  "verifyEmail",
  "resendVerification",
  "forgotPassword",
  "resetPassword",
  "mfaVerify",
  "mfaEnroll",
  "mfaDisable",
  "tokens",
  "introspect",
  "me",
  "sessionsList",
  "sessionRevoke",
  "sessionsAll",
  "logout",
  "changePassword",
  "jwks",
];

const rateLimits = Object.fromEntries(
  LIMIT_NAMES.map((name) => [name, { limit: 100_000, windowMs: 60_000 }]),
);

const child = spawn(process.execPath, [tsxCli, "src/app/bootstrap.ts"], {
  stdio: "inherit",
  env: {
    ...process.env,
    PORT: "3001",
    DATABASE_URL: "postgres://postgres:postgres@localhost:5432/auuth_test",
    EMAIL_PROVIDER: "console",
    SERVICE_API_KEY: "contract-test-service-key",
    RATE_LIMITS_JSON: JSON.stringify(rateLimits),
  },
});

child.on("error", (err) => {
  console.error("failed to start contract server:", err.message);
  process.exit(1);
});
child.on("exit", (code) => {
  process.exit(code ?? 1);
});
