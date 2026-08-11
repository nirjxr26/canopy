import { type FormEvent, useState } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { ApiError, mfaApi } from "../lib/api";
import { useSubmit } from "../lib/submit";
import { Alert } from "../ui/Alert";
import { Button } from "../ui/Button";
import { AuthShell, Card } from "../ui/Layout";
import { TextField } from "../ui/TextField";

type Mode = "totp" | "recovery";

export function MfaChallengePage() {
  const { setUser } = useAuth();
  const navigate = useNavigate();
  const { pending, error, run, setError } = useSubmit();
  const [mfaToken] = useState(() => sessionStorage.getItem("auuth.mfaToken"));
  const [code, setCode] = useState("");
  const [mode, setMode] = useState<Mode>("totp");
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [expired, setExpired] = useState(false);

  if (mfaToken === null) {
    return <Navigate to="/login" replace />;
  }

  const token = mfaToken;

  function toggleMode() {
    setMode((current) => (current === "totp" ? "recovery" : "totp"));
    setFieldError(null);
    setError(null);
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (code.trim() === "") {
      setFieldError(mode === "totp" ? "Enter the 6-digit code" : "Enter a recovery code");
      return;
    }
    setFieldError(null);
    void run(async () => {
      try {
        const { user: next } = await mfaApi.verify({ mfaToken: token, code: code.trim() });
        sessionStorage.removeItem("auuth.mfaToken");
        setUser(next);
        navigate("/", { replace: true });
      } catch (err) {
        if (err instanceof ApiError && err.code === "TOKEN_INVALID") {
          sessionStorage.removeItem("auuth.mfaToken");
          setExpired(true);
          return;
        }
        throw err;
      }
    });
  }

  return (
    <AuthShell footer="This code is single-use — new codes are issued on every sign-in.">
      <Card
        title="Two-factor authentication"
        subtitle="Enter the 6-digit code from your authenticator app, or use a recovery code."
      >
        {expired ? (
          <>
            <Alert tone="error">This code expired. Please sign in again.</Alert>
            <div className="inline-form__actions">
              <Link to="/login">
                <Button>Back to sign in</Button>
              </Link>
            </div>
          </>
        ) : (
          <>
            {error ? <Alert tone="error">{error}</Alert> : null}
            <form onSubmit={onSubmit} noValidate>
              <TextField
                label={mode === "totp" ? "Authentication code" : "Recovery code"}
                type="text"
                inputMode={mode === "totp" ? "numeric" : undefined}
                autoComplete="one-time-code"
                maxLength={mode === "totp" ? 6 : undefined}
                placeholder={mode === "totp" ? "123456" : "Enter your recovery code"}
                value={code}
                error={fieldError}
                onChange={(e) => setCode(e.target.value)}
              />
              <Button type="submit" block loading={pending}>
                Verify
              </Button>
            </form>
            <div className="inline-form__actions">
              <Button variant="ghost" onClick={toggleMode}>
                {mode === "totp" ? "Use a recovery code" : "Use the authenticator app"}
              </Button>
            </div>
          </>
        )}
      </Card>
    </AuthShell>
  );
}
