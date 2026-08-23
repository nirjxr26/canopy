import type { ReactNode } from "react";
import { Logo } from "./Logo";
import { Sidebar } from "./Sidebar";

export function AppShell({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <div className="min-h-dvh flex flex-col md:flex-row">
      <Sidebar />
      <main className="flex-1 min-w-0 px-5 py-6 md:px-10 md:py-10">{children}</main>
    </div>
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
