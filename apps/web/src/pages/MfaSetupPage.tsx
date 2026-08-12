import { type ReactNode, type SubmitEvent, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import QRCode from "qrcode";
import { ApiError, mfaApi } from "../lib/api";
import { useSubmit } from "../lib/submit";
import { Alert } from "../ui/Alert";
import { Button } from "../ui/Button";
import { AuthShell, Card } from "../ui/Layout";
import { TextField } from "../ui/TextField";

type Step = "enroll" | "verify" | "codes";

const STEP_META: Record<Step, { title: string; subtitle: string }> = {
  enroll: {
    title: "Add your authenticator app",
    subtitle: "Scan the QR code with your authenticator app to link your account.",
  },
  verify: {
    title: "Verify your code",
    subtitle: "Enter the 6-digit code shown in your authenticator app.",
  },
  codes: {
    title: "Recovery codes",
    subtitle: "Save these in a safe place before you continue.",
  },
};

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
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);
  const started = useRef(false);

  async function doEnroll() {
    try {
      const result = await mfaApi.enroll();
      setSecret(result.secret);
      const dataUrl = await QRCode.toDataURL(result.otpauthUrl, {
        width: 220,
        margin: 2,
        color: { dark: "#000000", light: "#FFFFFF" },
      });
      setQrDataUrl(dataUrl);
    } catch (err) {
      console.error("Failed to generate MFA QR code:", err);
      throw err;
    }
  }

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void enrollRun(doEnroll);
  }, [enrollRun]);

  function copySecret() {
    if (secret !== null) {
      void navigator.clipboard.writeText(secret);
      setCopiedSecret(true);
      setTimeout(() => setCopiedSecret(false), 2000);
    }
  }

  function copyCodes() {
    if (recoveryCodes !== null) {
      void navigator.clipboard.writeText(recoveryCodes.join("\n"));
      setCopiedCodes(true);
      setTimeout(() => setCopiedCodes(false), 2000);
    }
  }

  function onConfirm(event: SubmitEvent<HTMLFormElement>) {
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

  function renderEnrollContent(): ReactNode {
    if (enrollError !== null) {
      return (
        <>
          <Alert tone="error">{enrollError}</Alert>
          <div className="flex gap-2.5 mt-2">
            <Button variant="ghost" onClick={() => void enrollRun(doEnroll)}>
              Try again
            </Button>
          </div>
        </>
      );
    }
    if (qrDataUrl === null) {
      return (
        <div className="flex flex-col items-center justify-center gap-3 my-6">
          <span className="w-5 h-5 border-2 border-accent/25 border-t-accent rounded-full animate-spin" aria-hidden="true" />
          <p className="text-sm text-text-muted">Generating your secret...</p>
        </div>
      );
    }
    return (
      <>
        <div className="bg-white p-2.5 rounded-lg w-[220px] h-[220px] mx-auto mb-5 flex items-center justify-center border border-border">
          <img className="block w-full h-full object-contain" src={qrDataUrl} alt="QR code for authenticator app" />
        </div>
        <p className="text-[12.5px] text-text-faint mb-3">
          Open your authenticator app, tap &quot;Add account&quot;, and scan the QR code
          below. Can&apos;t scan it? Enter the secret manually.
        </p>
        <div className="flex flex-col gap-1.5 mb-4">
          <span className="text-xs font-medium text-text">Manual entry</span>
          <div className="flex items-center gap-2">
            <code className="flex-1 text-center font-mono text-xs bg-bg-elevated border border-border rounded-md px-2 py-1 text-text-muted tracking-wider overflow-hidden text-ellipsis whitespace-nowrap">
              {secret}
            </code>
            <Button variant="ghost" onClick={copySecret}>
              {copiedSecret ? "✓ Copied" : "Copy"}
            </Button>
          </div>
        </div>
        <Button block onClick={() => setStep("verify")}>
          Continue
        </Button>
        <div className="flex gap-2.5 mt-2">
          <Button variant="ghost" onClick={() => navigate("/")}>
            Not now
          </Button>
        </div>
      </>
    );
  }

  function renderVerifyContent(): ReactNode {
    return (
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
    );
  }

  function renderCodesContent(): ReactNode {
    return (
      <>
        <Alert tone="info">
          Store these somewhere safe — you&apos;ll need them if you lose your authenticator.
          Each can be used only once.
        </Alert>
        <div className="grid grid-cols-2 gap-2 mb-4">
          {recoveryCodes !== null
            ? recoveryCodes.map((recoveryCode) => (
                <code key={recoveryCode} className="font-mono text-xs text-center bg-bg-elevated border border-border rounded-md px-2 py-1 text-text-muted tracking-wider">
                  {recoveryCode}
                </code>
              ))
            : null}
        </div>
        <div className="flex gap-2.5 mb-3">
          <Button variant="ghost" onClick={copyCodes}>
            {copiedCodes ? "✓ Copied" : "Copy codes"}
          </Button>
        </div>
        <Button block onClick={() => navigate("/")}>
          Done
        </Button>
      </>
    );
  }

  return (
    <AuthShell footer="Recovery codes are shown only once — keep them somewhere safe.">
      <Card title={STEP_META[step].title} subtitle={STEP_META[step].subtitle}>
        {step === "enroll" ? renderEnrollContent() : null}
        {step === "verify" ? renderVerifyContent() : null}
        {step === "codes" ? renderCodesContent() : null}
      </Card>
    </AuthShell>
  );
}