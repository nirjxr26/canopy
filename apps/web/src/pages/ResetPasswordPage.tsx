import { type FormEvent, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { authApi, assertPasswordValid } from "../lib/api";
import { useSubmit } from "../lib/submit";
import { Alert } from "../ui/Alert";
import { Button } from "../ui/Button";
import { AuthShell, Card } from "../ui/Layout";
import { TextField } from "../ui/TextField";

export function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") ?? "";
  const { pending, error, run } = useSubmit();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [fieldErrors, setFieldErrors] = useState<{ password?: string; confirm?: string }>({});
  const [done, setDone] = useState(false);

  function validate(): boolean {
    const next: { password?: string; confirm?: string } = {};
    const passwordError = assertPasswordValid(password);
    if (passwordError) next.password = passwordError;
    if (confirm !== password) next.confirm = "Passwords do not match";
    setFieldErrors(next);
    return Object.keys(next).length === 0;
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (token === "") return;
    if (!validate()) return;
    void run(async () => {
      await authApi.resetPassword(token, password);
      setDone(true);
    });
  }

  return (
    <AuthShell footer="This link is single-use — all other sessions are signed out on reset.">
      <Card title="Set a new password" subtitle="Choose a strong password to protect your account.">
        {error ? <Alert tone="error">{error}</Alert> : null}
        {token === "" ? (
          <>
            <Alert tone="error">
              This link is missing its reset token. Use the link from your email and try again.
            </Alert>
            <div className="inline-form__actions">
              <Link to="/forgot-password">
                <Button variant="ghost">Request a new link</Button>
              </Link>
            </div>
          </>
        ) : done ? (
          <>
            <Alert tone="success">Your password has been reset. You can now sign in.</Alert>
            <div className="inline-form__actions">
              <Link to="/login">
                <Button>Go to sign in</Button>
              </Link>
            </div>
          </>
        ) : (
          <form onSubmit={onSubmit} noValidate>
            <TextField
              label="New password"
              type="password"
              autoComplete="new-password"
              placeholder="At least 12 characters"
              value={password}
              error={fieldErrors.password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <TextField
              label="Confirm new password"
              type="password"
              autoComplete="new-password"
              placeholder="Repeat your new password"
              value={confirm}
              error={fieldErrors.confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
            <Button type="submit" block loading={pending}>
              Reset password
            </Button>
          </form>
        )}
      </Card>
    </AuthShell>
  );
}
