import { type FormEvent, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import QRCode from "qrcode";
import { ApiError, mfaApi } from "../lib/api";
import { useSubmit } from "../lib/submit";
import { Alert } from "../ui/Alert";
import { Button } from "../ui/Button";
import { AuthShell, Card } from "../ui/Layout";
import { TextField } from "../ui/TextField";

type Step = "enroll" | "verify" | "codes";

export function MfaSetupPage() {
  const navigate = useNavigate();
  const { error: enrollError, run: enrollRun } = useSubmit();
  const { pending: confirming, error: confirmError, run: confirmRun } = useSubmit();
  const [step, setStep] = useState<Step>("enroll");
  const [secret, setSecret] = useState<string | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const started = useRef(false);

  async function doEnroll() {
    const result = await mfaApi.enroll();
    setSecret(result.secret);
    const dataUrl = await QRCode.toDataURL(result.otpauthUrl, {
      width: 220,
      margin: 1,
      color: { dark: "#141414", light: "#FFFFFF" },
    });
    setQrDataUrl(dataUrl);
  }

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void enrollRun(doEnroll);
  }, [enrollRun]);

  function copySecret() {
    if (secret !== null) void navigator.clipboard.writeText(secret);
  }

  function copyCodes() {
    if (recoveryCodes !== null) void navigator.clipboard.writeText(recoveryCodes.join("\n"));
  }

  function onConfirm(event: FormEvent) {
    event.preventDefault();
    if (secret === null || code.trim() === "") {
      setFieldError("Enter the 6-digit code");
      return;
    }
    setFieldError(null);
    void confirmRun(async () => {
      try {
        const result = await mfaApi.confirm({ secret, code: code.trim() });
        setRecoveryCodes(result.recoveryCodes);
        setStep("codes");
      } catch (err) {
        if (err instanceof ApiError && err.code === "CONFLICT") {
          window.alert("2FA is already enabled");
          navigate("/");
          return;
        }
        throw err;
      }
    });
  }

  return (
    <AuthShell footer="Recovery codes are shown only once — keep them somewhere safe.">
      <Card
        title={
          step === "enroll"
            ? "Add your authenticator app"
            : step === "verify"
              ? "Verify your code"
              : "Recovery codes"
        }
        subtitle={
          step === "enroll"
            ? "Scan the QR code with your authenticator app to link your account."
            : step === "verify"
              ? "Enter the 6-digit code shown in your authenticator app."
              : "Save these in a safe place before you continue."
        }
      >
        {step === "enroll" ? (
          enrollError !== null ? (
            <>
              <Alert tone="error">{enrollError}</Alert>
              <div className="inline-form__actions">
                <Button variant="ghost" onClick={() => void enrollRun(doEnroll)}>
                  Try again
                </Button>
              </div>
            </>
          ) : qrDataUrl === null ? (
            <div className="inline-form">
              <span className="spinner spinner--plain" aria-hidden="true" />
              <p>Generating your secret...</p>
            </div>
          ) : (
            <>
              <img className="mfa-qr" src={qrDataUrl} alt="QR code for authenticator app" />
              <p className="field__hint">
                Open your authenticator app, tap &quot;Add account&quot;, and scan the QR code
                below. Can&apos;t scan it? Enter the secret manually.
              </p>
              <div className="field">
                <label className="field__label">Manual entry</label>
                <div className="mfa-secret">
                  <code className="code-chip">{secret}</code>
                  <Button variant="ghost" onClick={copySecret}>
                    Copy
                  </Button>
                </div>
              </div>
              <Button block onClick={() => setStep("verify")}>
                Continue
              </Button>
              <div className="inline-form__actions">
                <Button variant="ghost" onClick={() => navigate("/")}>
                  Not now
                </Button>
              </div>
            </>
          )
        ) : null}
        {step === "verify" ? (
          <>
            {confirmError ? <Alert tone="error">{confirmError}</Alert> : null}
            <form onSubmit={onConfirm} noValidate>
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
              <Button type="submit" block loading={confirming}>
                Confirm
              </Button>
            </form>
          </>
        ) : null}
        {step === "codes" ? (
          <>
            <Alert tone="info">
              Store these somewhere safe — you&apos;ll need them if you lose your authenticator.
              Each can be used only once.
            </Alert>
            <div className="mfa-codes">
              {recoveryCodes !== null
                ? recoveryCodes.map((recoveryCode) => (
                    <code key={recoveryCode} className="code-chip">
                      {recoveryCode}
                    </code>
                  ))
                : null}
            </div>
            <div className="inline-form__actions">
              <Button variant="ghost" onClick={copyCodes}>
                Copy codes
              </Button>
            </div>
            <Button block onClick={() => navigate("/")}>
              Done
            </Button>
          </>
        ) : null}
      </Card>
    </AuthShell>
  );
}