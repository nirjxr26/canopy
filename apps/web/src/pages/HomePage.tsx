import { useAuth } from "../lib/auth";
import { AppShell } from "../ui/Layout";

export function HomePage() {
  const { user } = useAuth();

  if (user === null) {
    return null;
  }

  return (
    <AppShell>
      <h1 className="m-0 text-xl font-semibold tracking-tight">Home</h1>
      <p className="m-0 mt-1 text-sm text-text-muted">
        {user.firstName ? `Welcome back, ${user.firstName}.` : "Welcome back."}
      </p>
    </AppShell>
  );
}