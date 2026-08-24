import { useEffect, useRef, useState } from "react";
import { Alert } from "./Alert";
import { Button } from "./Button";

/**
 * One-time display of recovery codes with copy affordance.
 * Codes live in memory only (R-19) — the caller owns the save-gate UX.
 */
export function RecoveryCodes({ codes }: Readonly<{ codes: readonly string[] }>) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<number | undefined>(undefined);
  useEffect(
    () => () => {
      if (timer.current !== undefined) window.clearTimeout(timer.current);
    },
    [],
  );

  function copy() {
    void navigator.clipboard.writeText(codes.join("\n"));
    setCopied(true);
    if (timer.current !== undefined) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setCopied(false), 2000);
  }

  return (
    <>
      <Alert tone="info">Save these somewhere safe. Each can be used only once.</Alert>
      <div className="grid grid-cols-2 gap-2 my-3">
        {codes.map((code) => (
          <code
            key={code}
            className="font-mono text-xs text-center bg-bg-elevated border border-border rounded-md px-2 py-1 text-text-muted tracking-wider"
          >
            {code}
          </code>
        ))}
      </div>
      <Button variant="ghost" onClick={copy}>
        {copied ? "✓ Copied" : "Copy codes"}
      </Button>
    </>
  );
}
