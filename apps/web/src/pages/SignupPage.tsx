import { type SubmitEvent, useState } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { useSubmit } from "../lib/submit";
import { assertPasswordValid, isEmail } from "../lib/api";
import { Alert } from "../ui/Alert";
import { Button } from "../ui/Button";
import { AuthShell, Card } from "../ui/Layout";
import { PasswordField } from "../ui/PasswordField";
import { PasswordPolicy } from "../ui/PasswordPolicy";
import { TextField } from "../ui/TextField";

export function SignupPage() {
  const { user, signup } = useAuth();
  const navigate = useNavigate();
  const { pending, error, run } = useSubmit();
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [fieldErrors, setFieldErrors] = useState<{ email?: string; password?: string; confirm?: string }>({});
  const [done, setDone] = useState(false);
  const [devLink, setDevLink] = useState<string | null>(null);

  if (user !== null) {
    return <Navigate to="/" replace />;
  }

  if (done) {
    return (
      <AuthShell footer="Didn't get it? Head back and request a new verification email.">
        <Card title="Check your inbox" subtitle="Almost there — we need to confirm your email address.">
          <Alert tone="success">
            A verification link has been sent to <strong>{email}</strong>. It expires in 24 hours.
          </Alert>
          {devLink !== null ? (
            <Alert tone="info">
              Dev mode: verification emails aren't really sent, so here's your link —{" "}
              <a href={devLink}>{devLink}</a>
            </Alert>
          ) : null}
          <div className="inline-form__actions">
            <Button variant="ghost" onClick={() => navigate("/login")}>
              Back to sign in
            </Button>
          </div>
        </Card>
      </AuthShell>
    );
  }

  function validate(): boolean {
    const next: { email?: string; password?: string; confirm?: string } = {};
    if (!isEmail(email)) next.email = "Enter a valid email address";
    const passwordError = assertPasswordValid(password);
    if (passwordError) next.password = passwordError;
    if (confirm !== password) next.confirm = "Passwords do not match";
    setFieldErrors(next);
    return Object.keys(next).length === 0;
  }

  function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!validate()) return;
    void run(async () => {
      const result = await signup({ email, password, firstName: fullName.trim() || undefined });
      setDevLink(result.devEmailLink ?? null);
      setDone(true);
    });
  }

  return (
    <AuthShell>
      <Card title="Create your account" subtitle="Sign up in under a minute. No credit card required.">
        {error ? <Alert tone="error">{error}</Alert> : null}
        <form onSubmit={onSubmit} noValidate>
          <TextField
            label="Full name"
            autoComplete="name"
            placeholder="Jane Doe"
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
          />
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
            autoComplete="new-password"
            placeholder="At least 12 characters"
            value={password}
            error={fieldErrors.password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <PasswordField
            label="Confirm password"
            autoComplete="new-password"
            placeholder="Repeat your password"
            value={confirm}
            error={fieldErrors.confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
          <PasswordPolicy password={password} />
          <Button type="submit" block loading={pending}>
            Create account
          </Button>
        </form>
        <div className="flex items-center justify-center gap-2 mt-6 text-text-muted text-[13.5px]">
          <span>
            Already have an account? <Link to="/login">Sign in</Link>
          </span>
        </div>
      </Card>
    </AuthShell>
  );
}
