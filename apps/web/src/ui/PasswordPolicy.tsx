import { getPasswordRequirements } from "../lib/api";

export function PasswordPolicy({ password }: { password: string }) {
  if (password.length === 0) return null;

  const requirements = getPasswordRequirements(password);

  return (
    <div className="flex flex-col gap-1.5 my-3 p-3 bg-bg-elevated border border-border rounded-lg" role="list">
      {requirements.map((requirement) => (
        <div
          key={requirement.label}
          role="listitem"
          className={`flex items-center gap-2.5 text-xs transition-colors duration-150 ${
            requirement.met ? "text-success font-medium" : "text-text-faint opacity-70"
          }`}
        >
          <span
            className={`inline-flex items-center justify-center w-4 h-4 text-[11px] font-bold rounded-full border ${
              requirement.met
                ? "bg-success/15 border-success/40 text-success"
                : "bg-text-faint/10 border-text-faint/30 text-text-faint"
            }`}
            aria-hidden="true"
          >
            {requirement.met ? "✓" : "✕"}
          </span>
          <span>{requirement.label}</span>
        </div>
      ))}
    </div>
  );
}
