import { type SubmitEvent, useState } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { authApi, isEmail } from "../lib/api";
import { useSubmit } from "../lib/submit";
import { Alert } from "../ui/Alert";
import { Button } from "../ui/Button";
import { AuthShell, Card } from "../ui/Layout";
import { PasswordField } from "../ui/PasswordField";
import { TextField } from "../ui/TextField";

export function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const { pending, error, run } = useSubmit();
  const resend = useSubmit();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [keepSignedIn, setKeepSignedIn] = useState(true);
  const [fieldErrors, setFieldErrors] = useState<{ email?: string; password?: string }>({});
  const [resendMessage, setResendMessage] = useState<{ tone: "success" | "info"; text: string; link?: string } | null>(null);

  function sendVerification() {
    void resend.run(async () => {
      await authApi.resendVerification(email);
      setResendMessage({
        tone: "info",
        text: "If this account exists and isn't verified yet, a new verification email is on its way.",
      });
    });
  }

  if (user !== null) {
    return <Navigate to="/" replace />;
  }

  function validate(): boolean {
    const next: { email?: string; password?: string } = {};
    if (!isEmail(email)) next.email = "Enter a valid email address";
    if (password.length === 0) next.password = "Enter your password";
    setFieldErrors(next);
    return Object.keys(next).length === 0;
  }

  function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!validate()) return;
    void run(async () => {
      const result = await login(email, password, keepSignedIn);
      if ("mfaRequired" in result) {
        const from = (location.state as { from?: string } | null)?.from ?? "/";
        navigate("/mfa", { state: { from, mfaToken: result.mfaToken } });
      }
    });
  }

  return (
    <AuthShell>
      <Card title="Welcome back" subtitle="Sign in to your account to continue.">
        {error ? <Alert tone="error">{error}</Alert> : null}
        {resendMessage !== null ? (
          <Alert tone={resendMessage.tone}>{resendMessage.text}</Alert>
        ) : null}
        <form onSubmit={onSubmit} noValidate>
          <TextField
            label="Email"
            type="email"
            autoComplete="email"
            placeholder="you@example.com"
            value={email}
            error={fieldErrors.email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <PasswordField
            label="Password"
            autoComplete="current-password"
            placeholder="••••••••••••"
            value={password}
            error={fieldErrors.password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <div className="flex items-center justify-between mt-1 text-text-muted text-[13.5px]">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={keepSignedIn}
                onChange={(e) => setKeepSignedIn(e.target.checked)}
                className="size-4 accent-[var(--color-accent)]"
              />
              <span>Remember me</span>
            </label>
            <Link to="/forgot-password" className="hover:text-text">
              Forgot password?
            </Link>
          </div>
          <Button type="submit" block loading={pending} className="mt-4">
            Sign in
          </Button>
        </form>
        <div className="flex items-center justify-center gap-2 mt-6 text-text-muted text-[13.5px]">
          <span>
            Don't have an account?{" "}
            <Link to="/signup">Sign up</Link>
          </span>
        </div>
        {/* Always available: the endpoint is enumeration-safe and rate-limited,
            so the error never needs to reveal account state (C-3). */}
        <div className="flex items-center justify-center gap-2 mt-3">
          <Button variant="ghost" loading={resend.pending} onClick={sendVerification}>
            Resend verification email
          </Button>
        </div>
      </Card>
    </AuthShell>
  );
}
