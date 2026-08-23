import { type ReactNode, type SubmitEvent, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { assertPasswordValid, authApi, mfaApi } from "../lib/api";
import { type SubmitState, useSubmit } from "../lib/submit";
import { StatusValue, VerifiedBadge } from "./AccountSettingsStatus";
import { Alert } from "./Alert";
import { Button } from "./Button";
import { PasswordField } from "./PasswordField";
import { TextField } from "./TextField";

type View = "list" | "password" | "2fa" | "codes";

export function AccountSettingsSecurity() {
  const { user, refresh } = useAuth();
  const navigate = useNavigate();
  const resendSubmit = useSubmit();
  const changeSubmit = useSubmit();
  const disableSubmit = useSubmit();
  const regenerateSubmit = useSubmit();
  const [resendSent, setResendSent] = useState(false);
  const [changed, setChanged] = useState(false);
  const [view, setView] = useState<View>("list");
  const [password, setPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [code, setCode] = useState("");
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [copied, setCopied] = useState(false);
  // Clear copy-feedback timer on unmount (L-85).
  const copyTimer = useRef<number | undefined>(undefined);
  useEffect(() => () => {
    if (copyTimer.current !== undefined) window.clearTimeout(copyTimer.current);
  }, []);

  // Shared transient inputs must not bleed between sub-views.
  function switchView(next: View) {
    setPassword("");
    setNewPassword("");
    setConfirmPassword("");
    setCode("");
    setFieldError(null);
    setView(next);
  }

  if (user === null) {
    return null;
  }

  const onResend = () => {
    setResendSent(false);
    void resendSubmit.run(async () => {
      await authApi.resendVerification(user.email);
      setResendSent(true);
    });
  };

  function onChangePassword(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (newPassword !== confirmPassword) {
      setFieldError("Passwords don't match");
      return;
    }
    const invalid = assertPasswordValid(newPassword);
    if (invalid !== null) {
      setFieldError(invalid);
      return;
    }
    setFieldError(null);
    void changeSubmit.run(async () => {
      await authApi.changePassword({ currentPassword: password, newPassword });
      setPassword("");
      setNewPassword("");
      setConfirmPassword("");
      switchView("list");
      setChanged(true);
      await refresh();
    });
  }

  function onDisable(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (code.trim() === "") {
      setFieldError("Enter the 6-digit code");
      return;
    }
    setFieldError(null);
    void disableSubmit.run(async () => {
      await mfaApi.disable({ currentPassword: password, code: code.trim() });
      setPassword("");
      setCode("");
      switchView("list");
      await refresh();
    });
  }

  function onRegenerate(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (code.trim() === "") {
      setFieldError("Enter the 6-digit code");
      return;
    }
    setFieldError(null);
    void regenerateSubmit.run(async () => {
      const result = await mfaApi.regenerateRecoveryCodes({ code: code.trim() });
      setRecoveryCodes(result.recoveryCodes);
      setCode("");
    });
  }

  function copyCodes() {
    if (recoveryCodes !== null) {
      void navigator.clipboard.writeText(recoveryCodes.join("\n"));
      setCopied(true);
      if (copyTimer.current !== undefined) window.clearTimeout(copyTimer.current);
      copyTimer.current = window.setTimeout(() => setCopied(false), 2000);
    }
  }

  const onManageMfa = () => {
    if (user.mfaEnabled) {
      switchView("2fa");
    } else {
      navigate("/mfa/setup");
    }
  };

  if (view === "password") {
    return (
      <ChangePasswordView
        submit={changeSubmit}
        fieldError={fieldError}
        password={password}
        newPassword={newPassword}
        confirmPassword={confirmPassword}
        onPassword={setPassword}
        onNewPassword={setNewPassword}
        onConfirmPassword={setConfirmPassword}
        onSubmit={onChangePassword}
        onForgot={() => navigate("/forgot-password")}
        onBack={() => switchView("list")}
      />
    );
  }

  if (view === "2fa") {
    return (
      <DisableTwoFactorView
        submit={disableSubmit}
        fieldError={fieldError}
        password={password}
        code={code}
        onPassword={setPassword}
        onCode={setCode}
        onSubmit={onDisable}
        onBack={() => switchView("list")}
      />
    );
  }

  if (view === "codes") {
    return (
      <RecoveryCodesView
        submit={regenerateSubmit}
        fieldError={fieldError}
        code={code}
        onCode={setCode}
        onSubmit={onRegenerate}
        recoveryCodes={recoveryCodes}
        copied={copied}
        onCopy={copyCodes}
        onBack={() => switchView("list")}
      />
    );
  }

  return (
    <SecurityListView
      user={user}
      resendSubmit={resendSubmit}
      resendSent={resendSent}
      changed={changed}
      onResend={onResend}
      onOpenPassword={() => switchView("password")}
      onManageMfa={onManageMfa}
      onOpenCodes={() => switchView("codes")}
    />
  );
}

function ChangePasswordView({
  submit,
  fieldError,
  password,
  newPassword,
  confirmPassword,
  onPassword,
  onNewPassword,
  onConfirmPassword,
  onSubmit,
  onForgot,
  onBack,
}: Readonly<{
  submit: SubmitState;
  fieldError: string | null;
  password: string;
  newPassword: string;
  confirmPassword: string;
  onPassword: (value: string) => void;
  onNewPassword: (value: string) => void;
  onConfirmPassword: (value: string) => void;
  onSubmit: (event: SubmitEvent<HTMLFormElement>) => void;
  onForgot: () => void;
  onBack: () => void;
}>) {
  return (
    <DetailView
      title="Change password"
      description="Use at least 12 characters. Longer is stronger — avoid passwords you've used elsewhere."
      onBack={onBack}
    >
      {submit.error ? <Alert tone="error">{submit.error}</Alert> : null}
      <form onSubmit={onSubmit} noValidate className="flex flex-col gap-0">
        <PasswordField
          label="Current password"
          autoComplete="current-password"
          placeholder="Your current password"
          value={password}
          error={fieldError}
          onChange={(e) => onPassword(e.target.value)}
        />
        <PasswordField
          label="New password"
          autoComplete="new-password"
          placeholder="Your new password"
          value={newPassword}
          onChange={(e) => onNewPassword(e.target.value)}
        />
        <PasswordField
          label="Confirm new password"
          autoComplete="new-password"
          placeholder="Repeat your new password"
          value={confirmPassword}
          onChange={(e) => onConfirmPassword(e.target.value)}
        />
        <Button type="submit" loading={submit.pending}>
          Update password
        </Button>
      </form>
      <button
        type="button"
        onClick={onForgot}
        className="self-start mt-3 text-sm text-accent font-medium bg-transparent border-0 p-0 cursor-pointer hover:underline"
      >
        Forgot password?
      </button>
    </DetailView>
  );
}

function DisableTwoFactorView({
  submit,
  fieldError,
  password,
  code,
  onPassword,
  onCode,
  onSubmit,
  onBack,
}: Readonly<{
  submit: SubmitState;
  fieldError: string | null;
  password: string;
  code: string;
  onPassword: (value: string) => void;
  onCode: (value: string) => void;
  onSubmit: (event: SubmitEvent<HTMLFormElement>) => void;
  onBack: () => void;
}>) {
  return (
    <DetailView
      title="Two-factor authentication"
      description="Enter your password and a code from your authenticator app to turn off two-factor authentication."
      onBack={onBack}
    >
      {submit.error ? <Alert tone="error">{submit.error}</Alert> : null}
      <form onSubmit={onSubmit} noValidate className="flex flex-col gap-0">
        <PasswordField
          label="Current password"
          autoComplete="current-password"
          placeholder="Your password"
          value={password}
          onChange={(e) => onPassword(e.target.value)}
        />
        <TextField
          label="Authentication code"
          type="text"
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={6}
          placeholder="123456"
          value={code}
          error={fieldError}
          onChange={(e) => onCode(e.target.value)}
        />
        <Button type="submit" loading={submit.pending}>
          Disable 2FA
        </Button>
      </form>
    </DetailView>
  );
}

function RecoveryCodesView({
  submit,
  fieldError,
  code,
  onCode,
  onSubmit,
  recoveryCodes,
  copied,
  onCopy,
  onBack,
}: Readonly<{
  submit: SubmitState;
  fieldError: string | null;
  code: string;
  onCode: (value: string) => void;
  onSubmit: (event: SubmitEvent<HTMLFormElement>) => void;
  recoveryCodes: string[] | null;
  copied: boolean;
  onCopy: () => void;
  onBack: () => void;
}>) {
  return (
    <DetailView
      title="Recovery codes"
      description="Regenerating invalidates your existing recovery codes. Confirm with a code from your authenticator app."
      onBack={onBack}
    >
      {submit.error ? <Alert tone="error">{submit.error}</Alert> : null}
      {recoveryCodes === null ? (
        <form onSubmit={onSubmit} noValidate className="flex flex-col gap-0">
          <TextField
            label="Authentication code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            placeholder="123456"
            value={code}
            error={fieldError}
            onChange={(e) => onCode(e.target.value)}
          />
          <Button type="submit" loading={submit.pending}>
            Regenerate codes
          </Button>
        </form>
      ) : (
        <>
          <Alert tone="info">Save these somewhere safe. Each can be used only once.</Alert>
          <div className="grid grid-cols-2 gap-2 my-3">
            {recoveryCodes.map((recoveryCode) => (
              <code
                key={recoveryCode}
                className="font-mono text-xs text-center bg-bg-elevated border border-border rounded-md px-2 py-1 text-text-muted tracking-wider"
              >
                {recoveryCode}
              </code>
            ))}
          </div>
          <Button variant="ghost" onClick={onCopy}>
            {copied ? "✓ Copied" : "Copy codes"}
          </Button>
        </>
      )}
    </DetailView>
  );
}

function SecurityListView({
  user,
  resendSubmit,
  resendSent,
  changed,
  onResend,
  onOpenPassword,
  onManageMfa,
  onOpenCodes,
}: Readonly<{
  user: { email: string; emailVerified: boolean; mfaEnabled: boolean };
  resendSubmit: SubmitState;
  resendSent: boolean;
  changed: boolean;
  onResend: () => void;
  onOpenPassword: () => void;
  onManageMfa: () => void;
  onOpenCodes: () => void;
}>) {
  return (
    <section>
      <h2 className="m-0 text-base font-semibold tracking-tight">Security</h2>
      <p className="m-0 mt-[-1px] mb-4 text-sm text-text-muted">Security settings for your account.</p>

      {resendSubmit.error ? <Alert tone="error">{resendSubmit.error}</Alert> : null}
      {resendSent ? <Alert tone="success">Verification email sent.</Alert> : null}
      {changed ? <Alert tone="success">Password changed.</Alert> : null}

      <SettingRow
        label="Password"
        status={<StatusValue className="text-text-muted">Set or change your password.</StatusValue>}
        action="Change password"
        icon={<LockIcon />}
        iconClassName="bg-text-faint/15 text-text-muted"
        onClick={onOpenPassword}
      />

      <SettingRow
        label="Email verification"
        icon={<MailIcon />}
        iconClassName="bg-text-faint/15 text-text-muted"
        status={
          user.emailVerified ? (
            <StatusValue className="text-text-muted flex items-center gap-1.5 min-w-0">
              <span className="truncate">{user.email}</span>
              <VerifiedBadge />
            </StatusValue>
          ) : (
            <StatusValue className="text-text-muted flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-danger inline-block" aria-hidden="true" />
              <span>Not verified</span>
            </StatusValue>
          )
        }
        action={user.emailVerified ? undefined : "Verify email"}
        loading={resendSubmit.pending}
        onClick={() => {
          if (!user.emailVerified) onResend();
        }}
      />

      <SettingRow
        label="Two-factor authentication"
        icon={<ShieldIcon />}
        iconClassName="bg-text-faint/15 text-text-muted"
        status={
          user.mfaEnabled ? (
            <StatusValue className="text-text-muted flex items-center gap-1.5 flex-wrap">
              <span className="bg-success/15 text-success rounded-full px-2.5 py-0.5 text-xs font-medium shrink-0">Enabled</span>
              <span>with your authenticator app.</span>
            </StatusValue>
          ) : (
            <StatusValue className="text-text-muted">Disabled</StatusValue>
          )
        }
        action="Manage"
        onClick={onManageMfa}
      />

      <SettingRow
        label="Recovery codes"
        icon={<KeyIcon />}
        iconClassName="bg-text-faint/15 text-text-muted"
        status={
          user.mfaEnabled ? (
            <StatusValue className="text-text-muted">Shown once at setup.</StatusValue>
          ) : (
            <StatusValue className="text-text-muted">Requires two-factor authentication.</StatusValue>
          )
        }
        action={user.mfaEnabled ? "View / regenerate" : undefined}
        onClick={onOpenCodes}
      />
    </section>
  );
}

function DetailView({
  title,
  description,
  onBack,
  children,
}: Readonly<{
  title: string;
  description: string;
  onBack: () => void;
  children: ReactNode;
}>) {
  return (
    <section>
      <button
        type="button"
        onClick={onBack}
        aria-label="Back to security"
        className="flex items-center justify-center w-7 h-7 shrink-0 rounded-md text-text-muted bg-transparent border-0 p-0 cursor-pointer hover:text-text"
      >
        ←
      </button>
      <h2 className="m-0 mt-2 text-base font-semibold tracking-tight">{title}</h2>
      <p className="m-0 mt-1 mb-3 text-sm text-text-muted">{description}</p>
      <div className="pt-4">{children}</div>
    </section>
  );
}

export function SettingRow({
  label,
  status,
  action,
  icon,
  iconClassName,
  loading,
  onClick,
}: Readonly<{
  label: string;
  status?: ReactNode;
  action?: string;
  icon?: ReactNode;
  iconClassName?: string;
  loading?: boolean;
  onClick: () => void;
}>) {
  const iconTile = icon !== undefined ? (
    <span className={`shrink-0 flex items-center justify-center w-9 h-9 rounded-lg ${iconClassName ?? ""}`}>
      {icon}
    </span>
  ) : null;

  const body = (
    <span className="flex-1 min-w-0">
      <span className="block text-base font-medium text-text leading-5 truncate">{label}</span>
      {status !== undefined ? (
        <span className="block mt-0.5 text-sm text-text leading-5">{status}</span>
      ) : null}
    </span>
  );

  const actionGroup =
    action !== undefined ? (
      <span className="shrink-0 flex items-center gap-1.5">
        <span className="text-sm text-accent font-medium whitespace-nowrap">{action}</span>
        <span className="w-4 flex items-center justify-center text-text-faint group-hover:translate-x-0.5 transition-transform">›</span>
      </span>
    ) : null;

  if (action === undefined) {
    return (
      <div className="border-b border-border last:border-b-0 py-4 px-1 -mx-1 rounded-md">
        <div className="flex items-center gap-4">
          {iconTile}
          {body}
          {actionGroup}
        </div>
      </div>
    );
  }

  return (
    <div className="border-b border-border last:border-b-0">
      <button
        type="button"
        onClick={onClick}
        disabled={loading}
        className="group w-full flex items-center gap-4 py-4 px-1 -mx-1 rounded-md text-left cursor-pointer disabled:cursor-default"
      >
        {iconTile}
        {body}
        {actionGroup}
      </button>
    </div>
  );
}

function LockIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}

function MailIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="2" y="4" width="20" height="16" rx="2" ry="2" />
      <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
    </svg>
  );
}

function ShieldIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

function KeyIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="m21 2-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4" />
    </svg>
  );
}
