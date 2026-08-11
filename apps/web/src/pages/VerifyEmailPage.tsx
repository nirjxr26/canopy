import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { authApi } from "../lib/api";
import { useSubmit } from "../lib/submit";
import { Alert } from "../ui/Alert";
import { Button } from "../ui/Button";
import { AuthShell, Card } from "../ui/Layout";

type State = "checking" | "success" | "error";

export function VerifyEmailPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") ?? "";
  const [state, setState] = useState<State>("checking");
  const { pending, run } = useSubmit();
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    if (token === "") {
      setState("error");
      return;
    }
    void run(async () => {
      await authApi.verifyEmail(token);
      setState("success");
    });
  }, [token, run]);

  return (
    <AuthShell footer="Auuth keeps the link single-use — once used it can't be reused.">
      <Card title="Email verification" subtitle="Confirming your email address...">
        {state === "checking" ? (
          <div className="inline-form">
            <span className="spinner spinner--plain" aria-hidden="true" />
            <p>Verifying your email. This should only take a moment.</p>
          </div>
        ) : null}
        {state === "success" ? (
          <>
            <Alert tone="success">Your email has been verified. You can now sign in.</Alert>
            <div className="inline-form__actions">
              <Link to="/login">
                <Button>Go to sign in</Button>
              </Link>
            </div>
          </>
        ) : null}
        {state === "error" ? (
          <>
            <Alert tone="error">
              This verification link is invalid or has expired. Request a new one and try again.
            </Alert>
            <div className="inline-form">
              {pending ? null : (
                <Button
                  variant="ghost"
                  onClick={() => {
                    started.current = false;
                    setState("checking");
                  }}
                >
                  Try again
                </Button>
              )}
            </div>
          </>
        ) : null}
      </Card>
    </AuthShell>
  );
}
