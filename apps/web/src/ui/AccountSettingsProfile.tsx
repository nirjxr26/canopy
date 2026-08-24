import { type SubmitEvent, useState } from "react";
import { useAuth } from "../lib/auth";
import { authApi } from "../lib/api";
import { useSubmit } from "../lib/submit";
import { Avatar, displayName } from "./Avatar";
import { StatusValue, VerifiedBadge, formatDate } from "./AccountSettingsStatus";
import { SettingRow } from "./AccountSettingsSecurity";
import { Alert } from "./Alert";
import { Button } from "./Button";
import { TextField } from "./TextField";

const STATUS_STYLES: Record<string, { label: string; color: string }> = {
  ACTIVE: { label: "Active", color: "var(--color-success)" },
  PENDING_VERIFICATION: { label: "Pending verification", color: "var(--color-warning)" },
  SUSPENDED: { label: "Suspended", color: "var(--color-suspended)" },
  LOCKED: { label: "Locked", color: "var(--color-danger)" },
  DEACTIVATED: { label: "Deactivated", color: "var(--color-text-muted)" },
};

export function AccountSettingsProfile() {
  const { user, refresh } = useAuth();
  const profileSubmit = useSubmit();
  const [editing, setEditing] = useState(false);
  const [firstNameInput, setFirstNameInput] = useState("");
  const [lastNameInput, setLastNameInput] = useState("");

  if (user === null) {
    return null;
  }

  const name = displayName(user.firstName, user.lastName);

  function onSave(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    void profileSubmit.run(async () => {
      // Send both fields so edits preserve the sibling name instead of
      // overwriting firstName with a concatenated full name.
      await authApi.updateProfile({ firstName: firstNameInput.trim(), lastName: lastNameInput.trim() });
      await refresh();
      setEditing(false);
    });
  }

  return (
    <section>
      <h2 className="m-0 text-base font-semibold tracking-tight">Profile</h2>
      <p className="m-0 mt-[-1px] mb-5 text-sm text-text-muted">Your account information.</p>

      <div className="flex items-center gap-4 pb-5 mb-1 border-b border-border">
        <Avatar name={name} email={user.email} size={56} />
        <div className="min-w-0">
          <p className="m-0 flex items-center gap-1.5 min-w-0 text-base font-medium text-text">
            <span className="truncate">{name ?? "—"}</span>
          </p>
          <p className="mt-0.5 m-0 flex items-center gap-1.5 min-w-0 text-sm text-text-muted">
            <span className="truncate">{user.email}</span>
            {user.emailVerified ? <VerifiedBadge /> : null}
          </p>
        </div>
      </div>

      {editing ? (
        <div className="border-b border-border last:border-b-0">
          <div className="py-4 px-1 -mx-1">
            <form onSubmit={onSave} noValidate className="flex flex-col gap-0">
              <TextField
                label="First name"
                autoComplete="given-name"
                placeholder="Jane"
                value={firstNameInput}
                onChange={(e) => setFirstNameInput(e.target.value)}
              />
              <TextField
                label="Last name"
                autoComplete="family-name"
                placeholder="Doe"
                value={lastNameInput}
                onChange={(e) => setLastNameInput(e.target.value)}
              />
              {profileSubmit.error ? <Alert tone="error">{profileSubmit.error}</Alert> : null}
              <div className="flex items-center gap-2">
                <Button type="submit" loading={profileSubmit.pending}>
                  Save
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => {
                    setEditing(false);
                    setFirstNameInput(user.firstName ?? "");
                    setLastNameInput(user.lastName ?? "");
                  }}
                >
                  Cancel
                </Button>
              </div>
            </form>
          </div>
        </div>
      ) : (
        <SettingRow
          label="Name"
          icon={<UserIcon />}
          iconClassName="bg-text-faint/15 text-text-muted"
          status={
            <StatusValue className="text-text-muted truncate block">{name ?? "No name set"}</StatusValue>
          }
          action="Edit"
          onClick={() => {
            setFirstNameInput(user.firstName ?? "");
            setLastNameInput(user.lastName ?? "");
            setEditing(true);
          }}
        />
      )}
      <SettingRow
        label="Account status"
        icon={<ShieldCheckIcon />}
        iconClassName="bg-text-faint/15 text-text-muted"
        status={
          <span
            className="block truncate text-sm font-medium leading-5"
            style={{ color: STATUS_STYLES[user.status]?.color }}
          >
            {STATUS_STYLES[user.status]?.label ?? user.status}
          </span>
        }
        onClick={() => {}}
      />
      <SettingRow
        label="Last login"
        icon={<ClockIcon />}
        iconClassName="bg-text-faint/15 text-text-muted"
        status={
          <StatusValue className="text-text-muted truncate block">
            {user.lastLoginAt !== null ? formatDate(user.lastLoginAt) : "Never"}
          </StatusValue>
        }
        onClick={() => {}}
      />
    </section>
  );
}

function UserIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  );
}

function ShieldCheckIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}

function ClockIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="10" />
      <polyline points="12 6 12 12 16 14" />
    </svg>
  );
}