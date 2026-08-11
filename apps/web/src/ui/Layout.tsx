import type { ReactNode } from "react";

export function Logo() {
  return (
    <span className="inline-flex items-center text-text text-3xl font-bold tracking-tight">
      Sentinel<span className="text-accent">X</span>
    </span>
  );
}

export function AuthShell({ children, footer }: Readonly<{ children: ReactNode; footer?: ReactNode }>) {
  return (
    <main className="min-h-dvh flex flex-col items-center justify-center p-6 gap-6">
      <div className="flex flex-col items-center gap-2">
        <Logo />
      </div>
      <div className="w-full max-w-[400px]">{children}</div>
      {footer ? <div className="text-text-faint text-xs">{footer}</div> : null}
    </main>
  );
}

export function Card({ title, subtitle, children }: Readonly<{ title: string; subtitle?: string; children: ReactNode }>) {
  return (
    <section className="bg-bg-card border border-border rounded-xl p-7">
      <h1 className="m-0 text-xl font-semibold text-center tracking-tight">{title}</h1>
      {subtitle ? <p className="text-center m-0 mb-8 text-text-muted text-sm">{subtitle}</p> : null}
      {children}
    </section>
  );
}
