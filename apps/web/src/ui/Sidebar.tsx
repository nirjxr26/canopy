import { NavLink } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { AccountSwitcher } from "./AccountSwitcher";
import { Logo } from "./Logo";

interface NavItem {
  to: string;
  label: string;
  end?: boolean;
}

const NAV_ITEMS: NavItem[] = [{ to: "/", label: "Home", end: true }];

export function Sidebar() {
  const { user } = useAuth();

  return (
    <aside className="w-full md:w-60 shrink-0 flex flex-col border-b md:border-b-0 md:border-r border-border bg-bg-card">
      <div className="px-5 py-4 md:py-6">
        <Logo />
      </div>
      <nav
        className="flex md:flex-col gap-1 px-3 pb-3 md:pb-4 md:flex-1 overflow-x-auto md:overflow-visible"
        aria-label="Main navigation"
      >
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              `whitespace-nowrap rounded-md px-3 py-2 text-sm font-medium transition-colors no-underline hover:no-underline ${
                isActive ? "bg-hover text-accent" : "text-text-muted hover:bg-hover"
              }`
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>
      {user !== null ? (
        <div className="border-t border-border px-3 py-3 md:px-4 md:py-4">
          <AccountSwitcher />
        </div>
      ) : null}
    </aside>
  );
}
