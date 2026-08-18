import { useEffect, useRef, useState } from "react";
import { useAuth } from "../lib/auth";
import { AccountSettingsProfile } from "./AccountSettingsProfile";
import { AccountSettingsSecurity } from "./AccountSettingsSecurity";
import { AccountSettingsSessions } from "./AccountSettingsSessions";
import { Button } from "./Button";

type Section = "profile" | "security" | "sessions";

const SECTIONS: { id: Section; label: string }[] = [
  { id: "profile", label: "Profile" },
  { id: "security", label: "Security" },
  { id: "sessions", label: "Sessions" },
];

export function AccountSettingsPopup({ open, onClose }: Readonly<{ open: boolean; onClose: () => void }>) {
  const { user } = useAuth();
  const [section, setSection] = useState<Section>("profile");
  const panelRef = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    if (!open) return;
    panelRef.current?.focus();
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        onClose();
        return;
      }
      if (event.key !== "Tab" || panelRef.current === null) return;
      const focusable = panelRef.current.querySelectorAll<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
      );
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open || user === null) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-40 overflow-y-auto bg-black/50 scrollbar-thin">
      <div className="flex min-h-full items-start md:items-center justify-center p-4 md:p-6">
        <dialog
          ref={panelRef}
          aria-label="Account settings"
          open
          className="w-full max-w-[900px] h-[680px] max-h-[90vh] flex flex-col outline-none bg-bg rounded-xl shadow-lg"
        >
          <div className="flex shrink-0 items-start justify-between gap-4 px-6 pt-6">
            <div>
              <h1 className="m-0 text-lg font-semibold tracking-tight">Account settings</h1>
              <p className="m-0 -mt-1 text-sm text-text-muted">Manage your account information and security.</p>
            </div>
            <Button variant="ghost" onClick={onClose} aria-label="Close account settings">
              ✕
            </Button>
          </div>

          <div className="p-6 pt-5 flex-1 min-h-0 overflow-hidden flex flex-col md:flex-row gap-6 items-stretch">
            <nav
              className="flex md:flex-col gap-1 md:w-44 shrink-0 w-full self-start"
              aria-label="Account settings sections"
            >
              {SECTIONS.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setSection(item.id)}
                  aria-current={section === item.id ? "true" : undefined}
                  className={`rounded-md px-3 py-2 text-sm font-medium transition-colors text-left cursor-pointer ${
                    section === item.id ? "bg-hover text-accent" : "text-text-muted"
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </nav>

            <div className="flex-1 min-w-0 min-h-0 w-full bg-bg-card rounded-lg p-5 overflow-y-auto scrollbar-thin">
              {section === "profile" && <AccountSettingsProfile />}
              {section === "security" && <AccountSettingsSecurity />}
              {section === "sessions" && <AccountSettingsSessions />}
            </div>
          </div>
        </dialog>
      </div>
    </div>
  );
}
