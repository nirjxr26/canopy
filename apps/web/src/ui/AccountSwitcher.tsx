import { useEffect, useRef, useState } from "react";
import { useAuth } from "../lib/auth";
import { useSubmit } from "../lib/submit";
import { AccountSettingsPopup } from "./AccountSettingsPopup";
import { Avatar, displayName } from "./Avatar";

export function AccountSwitcher() {
  const { user, logout } = useAuth();
  const logoutSubmit = useSubmit();
  const [open, setOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);

  // Esc closes the menu and returns focus to the trigger.
  useEffect(() => {
    if (!open) return;
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setOpen(false);
        triggerRef.current?.focus();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open]);

  if (user === null) {
    return null;
  }

  const name = displayName(user.firstName, user.lastName);

  return (
    <div className="relative">
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-haspopup="menu"
        aria-expanded={open}
        className="w-full flex items-center gap-3 rounded-md px-2 py-2 cursor-pointer transition-colors hover:bg-hover"
      >
        <Avatar name={name} email={user.email} size={36} />
        <span className="min-w-0 flex-1 text-left">
          <span className="block truncate text-sm font-medium text-text">{name ?? user.email}</span>
          {name !== null ? (
            <span className="block truncate text-xs text-text-faint">{user.email}</span>
          ) : null}
        </span>
      </button>

      {open ? (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} aria-hidden="true" />
          <div
            role="menu"
            className="absolute bottom-full left-0 right-0 z-20 mb-2 bg-bg-card border border-border rounded-lg shadow-lg p-1.5 flex flex-col"
          >
            <button
              role="menuitem"
              type="button"
              onClick={() => {
                setOpen(false);
                setSettingsOpen(true);
              }}
              className="w-full flex items-center gap-2 cursor-pointer rounded-md px-2 py-2 text-left text-sm text-text transition-colors hover:bg-hover"
            >
              <SettingsIcon />
              Manage Account
            </button>
          </div>
        </>
      ) : null}

      <button
        type="button"
        disabled={logoutSubmit.pending}
        aria-busy={logoutSubmit.pending}
        onClick={() => void logoutSubmit.run(() => logout())}
        className="w-full mt-1 flex items-center gap-3 rounded-md px-2 py-2 text-danger cursor-pointer transition-colors hover:bg-hover disabled:cursor-default"
      >
        <span className="flex items-center justify-center w-9 h-9 shrink-0">
          {logoutSubmit.pending ? (
            <span className="w-4 h-4 border-2 border-white/35 border-t-current rounded-full animate-spin" aria-hidden="true" />
          ) : (
            <SignOutIcon />
          )}
        </span>
        <span className="text-xs font-medium text-left">Sign out</span>
      </button>

      {logoutSubmit.error !== null ? (
        <p role="alert" className="mt-1 px-2 text-xs text-danger">
          {logoutSubmit.error}
        </p>
      ) : null}

      <AccountSettingsPopup open={settingsOpen} onClose={() => setSettingsOpen(false)} />
    </div>
  );
}

function SettingsIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="text-text-muted shrink-0"
      aria-hidden="true"
    >
      <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

function SignOutIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <polyline points="16 17 21 12 16 7" />
      <line x1="21" y1="12" x2="9" y2="12" />
    </svg>
  );
}
