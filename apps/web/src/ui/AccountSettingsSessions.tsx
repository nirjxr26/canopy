import { useEffect, useRef, useState } from "react";
import { useAuth } from "../lib/auth";
import { sessionsApi, type Session } from "../lib/api";
import { messageFrom } from "../lib/submit";
import { StatusValue, formatDate } from "./AccountSettingsStatus";
import { Alert } from "./Alert";
import { Button } from "./Button";

export function AccountSettingsSessions() {
  const { refresh } = useAuth();
  const [sessions, setSessions] = useState<Session[] | null>(null);
  const [sessionsError, setSessionsError] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [revokeError, setRevokeError] = useState<string | null>(null);
  const [revokeAllError, setRevokeAllError] = useState<string | null>(null);
  const [revokingAll, setRevokingAll] = useState(false);
  const started = useRef(false);

  async function loadSessions() {
    try {
      const result = await sessionsApi.list();
      setSessions(result.sessions);
      setSessionsError(null);
    } catch (err) {
      setSessionsError(messageFrom(err));
    }
  }

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void loadSessions();
  }, []);

  async function onRevoke(id: string) {
    setRevokingId(id);
    setRevokeError(null);
    try {
      await sessionsApi.revoke(id);
      await loadSessions();
      await refresh();
    } catch (err) {
      setRevokeError(messageFrom(err));
    } finally {
      setRevokingId(null);
    }
  }

  async function onRevokeAll() {
    setRevokingAll(true);
    setRevokeAllError(null);
    try {
      await sessionsApi.revokeAll();
      await loadSessions();
      await refresh();
    } catch (err) {
      setRevokeAllError(messageFrom(err));
    } finally {
      setRevokingAll(false);
    }
  }

  function renderSessionsContent() {
    if (sessions === null) {
      return <p className="text-sm text-text-muted mt-3">Loading sessions...</p>;
    }
    if (sessions.length === 0) {
      return <p className="text-sm text-text-muted mt-3">No active sessions.</p>;
    }
    return (
      <ul className="m-0 mt-3 p-0 list-none flex flex-col">
        {sessions.map((session) => {
          const mobile = /mobile|android|iphone|ipad/i.test(session.userAgent ?? "");
          return (
            <li key={session.id} className="border-b border-border last:border-b-0">
              <div className="group w-full flex items-center gap-4 py-4 px-1 -mx-1 rounded-md">
                <span className="shrink-0 flex items-center justify-center w-9 h-9 rounded-lg bg-text-faint/15 text-text-muted">
                  {mobile ? <SmartphoneIcon /> : <MonitorIcon />}
                </span>
                <span className="flex-1 min-w-0">
                  <span className="block text-base font-medium text-text leading-5 truncate">
                    {session.isCurrent ? "This device" : (session.userAgent ?? "Unknown device")}
                  </span>
                  <span className="block mt-0.5 text-sm text-text-muted leading-5 truncate">
                    {session.ipAddress ?? "Unknown IP"} · Last used {formatDate(session.lastUsedAt)}
                  </span>
                </span>
                {!session.isCurrent ? (
                  <button
                    type="button"
                    disabled={revokingId === session.id}
                    onClick={() => void onRevoke(session.id)}
                    className="shrink-0 text-sm text-danger font-medium whitespace-nowrap bg-transparent border-0 p-0 cursor-pointer hover:underline disabled:cursor-default"
                  >
                    {revokingId === session.id ? "Revoking…" : "Revoke"}
                  </button>
                ) : (
                  <StatusValue className="text-text-faint shrink-0">Current</StatusValue>
                )}
              </div>
            </li>
          );
        })}
      </ul>
    );
  }

  return (
    <section>
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="m-0 text-base font-semibold tracking-tight">Sessions</h2>
          <p className="m-0 mt-[-1px]  text-sm text-text-muted">Devices and browsers signed in to your account.</p>
        </div>
        <Button variant="ghost" loading={revokingAll} onClick={() => void onRevokeAll()}>
          Sign out of all devices
        </Button>
      </div>

      {revokeAllError ? <Alert tone="error">{revokeAllError}</Alert> : null}
      {revokeError ? <Alert tone="error">{revokeError}</Alert> : null}
      {sessionsError ? <Alert tone="error">{sessionsError}</Alert> : null}
      {renderSessionsContent()}
    </section>
  );
}

function MonitorIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
    </svg>
  );
}

function SmartphoneIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="5" y="2" width="14" height="20" rx="2" ry="2" />
      <line x1="12" y1="18" x2="12.01" y2="18" />
    </svg>
  );
}
