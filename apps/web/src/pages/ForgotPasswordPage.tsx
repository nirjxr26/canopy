import { type SubmitEvent, useState } from "react";
import { Link } from "react-router-dom";
import { authApi, isEmail } from "../lib/api";
import { useSubmit } from "../lib/submit";
import { Alert } from "../ui/Alert";
import { Button } from "../ui/Button";
import { AuthShell, Card } from "../ui/Layout";
import { TextField } from "../ui/TextField";

export function ForgotPasswordPage() {
  const { pending, error, run } = useSubmit();
  const [email, setEmail] = useState("");
  const [emailError, setEmailError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  function onSubmit(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!isEmail(email)) {
      setEmailError("Enter a valid email address");
      return;
    }
    setEmailError(null);
    void run(async () => {
      await authApi.forgotPassword(email);
      setDone(true);
    });
  }

  if (done) {
    return (
      <AuthShell footer="The reset link is single-use and expires in 30 minutes.">
        <Card title="Check your inbox" subtitle="If an account exists, a reset link is on its way.">
          <Alert tone="success">
            If <strong>{email}</strong> is registered, we've sent a password reset link to it. It
            expires in 30 minutes.
          </Alert>
          <div className="flex gap-2.5 mt-2">
            <Link to="/login">
              <Button variant="ghost">Back to sign in</Button>
            </Link>
          </div>
        </Card>
      </AuthShell>
    );
  }

  return (
    <AuthShell>
      <Card title="Forgot your password?" subtitle="Enter your email and we'll send you a reset link.">
        {error ? <Alert tone="error">{error}</Alert> : null}
        <form onSubmit={onSubmit} noValidate>
          <TextField
            label="Email"
            type="email"
            autoComplete="email"
            placeholder="you@example.com"
            value={email}
            error={emailError}
            onChange={(e) => setEmail(e.target.value)}
          />
          <Button type="submit" block loading={pending}>
            Send reset link
          </Button>
        </form>
        <div className="flex items-center justify-between gap-2 mt-3 text-text-muted text-[13.5px]">
          <span>
            Remembered it? <Link to="/login">Sign in</Link>
          </span>
        </div>
      </Card>
    </AuthShell>
  );
}
