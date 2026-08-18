import type { ReactNode } from "react";

export function StatusRow({ label, children }: Readonly<{ label: string; children: ReactNode }>) {
  return (
    <div className="flex items-center justify-between gap-4 py-4 border-b border-border last:border-b-0">
      <span className="text-base font-medium text-text leading-5">{label}</span>
      <div className="flex items-center gap-2.5">{children}</div>
    </div>
  );
}

export function StatusValue({ children, className }: Readonly<{ children: ReactNode; className?: string }>) {
  return <span className={`text-sm text-text font-medium leading-5 ${className ?? ""}`}>{children}</span>;
}

export function VerifiedBadge() {
  return (
    <span className="inline-flex items-center gap-1.5 bg-success/15 text-success rounded-full px-2.5 py-1 text-xs font-medium shrink-0">
      <span className="flex items-center justify-center w-4 h-4 rounded-full bg-success text-bg">
        <svg className="block" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M20 6 9 17l-5-5" />
        </svg>
      </span>
      <span>Verified</span>
    </span>
  );
}

export function formatDate(iso: string | null): string {
  if (iso === null) return "unknown time";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "unknown time";
  return date.toLocaleString();
}
