import { type FormEvent, useState } from "react";
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
  const [fieldErrors, setFieldErrors] = useState<{ email?: string; password?: string }>({});
  const [resendMessage, setResendMessage] = useState<{ tone: "success" | "info"; text: string; link?: string } | null>(null);

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

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (!validate()) return;
    void run(async () => {
      const result = await login(email, password);
      if ("mfaRequired" in result) {
        const from = (location.state as { from?: string } | null)?.from ?? "/";
        sessionStorage.setItem("auuth.mfaToken", result.mfaToken);
        navigate("/mfa", { state: { from } });
      }
    });
  }

  function onResend() {
    void resend.run(async () => {
      const result = await authApi.resendVerification(email);
      if (result.devEmailLink !== undefined) {
        setResendMessage({
          tone: "success",
          text: "A fresh verification link is ready — ",
          link: result.devEmailLink,
        });
      } else {
        setResendMessage({
          tone: "info",
          text: "If this account exists and isn't verified yet, a new verification email is on its way.",
        });
      }
    });
  }

  return (
    <AuthShell>
      <Card title="Welcome back" subtitle="Sign in to your account to continue.">
        {error ? <Alert tone="error">{error}</Alert> : null}
        {resendMessage !== null ? (
          <Alert tone={resendMessage.tone}>
            {resendMessage.text}
            {resendMessage.link !== undefined ? <a href={resendMessage.link}>{resendMessage.link}</a> : null}
          </Alert>
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
          <Button type="submit" block loading={pending}>
            Sign in
          </Button>
        </form>
        <div className="flex items-center justify-between gap-2 mt-3 text-text-muted text-[13.5px]">
          <Link to="/forgot-password">Forgot password?</Link>
          <Link to="/signup">Create an account</Link>
        </div>
        {error !== null ? (
          <div className="flex items-center justify-center gap-2 mt-4 text-text-muted text-[13.5px]">
            <Button variant="ghost" loading={resend.pending} onClick={onResend}>
              Email not verified? Resend the link
            </Button>
          </div>
        ) : null}
      </Card>
    </AuthShell>
  );
}
