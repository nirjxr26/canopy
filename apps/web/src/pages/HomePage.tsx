import { type FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { mfaApi } from "../lib/api";
import { useSubmit } from "../lib/submit";
import { Alert } from "../ui/Alert";
import { Button } from "../ui/Button";
import { AuthShell, Card } from "../ui/Layout";
import { TextField } from "../ui/TextField";

export function HomePage() {
  const { user, logout, refresh } = useAuth();
  const navigate = useNavigate();
  const logoutSubmit = useSubmit();
  const disableSubmit = useSubmit();
  const [code, setCode] = useState("");
  const [fieldError, setFieldError] = useState<string | null>(null);

  if (user === null) {
    return null;
  }

  function onDisable(event: FormEvent) {
    event.preventDefault();
    if (code.trim() === "") {
      setFieldError("Enter the 6-digit code");
      return;
    }
    setFieldError(null);
    void disableSubmit.run(async () => {
      await mfaApi.disable(code.trim());
      setCode("");
      await refresh();
    });
  }

  return (
    <AuthShell footer="Signed in with a server-side session — nothing sensitive is stored in the browser.">
      <>
        <Card title={`Hi${user.firstName ? ` ${user.firstName}` : ""}`} subtitle="You're signed in.">
          {logoutSubmit.error ? <Alert tone="error">{logoutSubmit.error}</Alert> : null}
          <div className="inline-form">
            <div className="inline-form__row">
              <span>Email</span>
              <strong>{user.email}</strong>
            </div>
            <div className="inline-form__row">
              <span>Status</span>
              <strong>{user.status}</strong>
            </div>
            <div className="inline-form__row">
              <span>Email verified</span>
              <strong>{user.emailVerified ? "Yes" : "No"}</strong>
            </div>
          </div>
          <div className="inline-form__actions">
            <Button
              variant="ghost"
              loading={logoutSubmit.pending}
              onClick={() => void logoutSubmit.run(() => logout().then(() => undefined))}
            >
              Sign out
            </Button>
          </div>
        </Card>
        <Card title="Two-factor authentication" subtitle="Protect your account with a second factor.">
          {!user.mfaEnabled ? (
            <>
              <p>Add an extra layer of security to your account.</p>
              <div className="inline-form__actions">
                <Button onClick={() => navigate("/mfa/setup")}>Enable two-factor authentication</Button>
              </div>
            </>
          ) : (
            <>
              <p>Two-factor authentication is on.</p>
              {disableSubmit.error ? <Alert tone="error">{disableSubmit.error}</Alert> : null}
              <form onSubmit={onDisable} noValidate>
                <TextField
                  label="Authentication code"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  placeholder="123456"
                  value={code}
                  error={fieldError}
                  onChange={(e) => setCode(e.target.value)}
                />
                <Button type="submit" loading={disableSubmit.pending}>
                  Disable
                </Button>
              </form>
            </>
          )}
        </Card>
      </>
    </AuthShell>
  );
}