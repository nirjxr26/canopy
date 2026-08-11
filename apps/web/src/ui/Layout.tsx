import type { ReactNode } from "react";

export function Logo() {
  return (
    <span className="logo">
      <span className="logo__mark" aria-hidden="true">
        A
      </span>
      auuth
    </span>
  );
}

export function AuthShell({ children, footer }: { children: ReactNode; footer?: ReactNode }) {
  return (
    <main className="auth-shell">
      <div className="auth-shell__brand">
        <Logo />
      </div>
      <div className="auth-shell__card">{children}</div>
      {footer ? <div className="auth-shell__footer">{footer}</div> : null}
    </main>
  );
}

export function Card({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <section className="card">
      <h1 className="card__title">{title}</h1>
      {subtitle ? <p className="card__subtitle">{subtitle}</p> : null}
      {children}
    </section>
  );
}
