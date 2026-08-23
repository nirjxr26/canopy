import { getPasswordRequirements } from "../lib/api";

export function PasswordPolicy({ password }: Readonly<{ password: string }>) {
  if (password.length === 0) return null;

  const requirements = getPasswordRequirements(password);

  return (
    <ul className="flex flex-col gap-1.5 my-3 p-3 bg-bg-elevated border border-border rounded-lg">
      {requirements.map((requirement) => (
        <li
          key={requirement.label}
          className={`flex items-center gap-2.5 text-xs transition-colors duration-150 ${
            requirement.met
              ? "text-success font-medium"
              : "text-text-faint opacity-70"
          }`}
        >
          <span
            className={`inline-flex items-center justify-center w-4 h-4 text-[11px] font-bold rounded-full border ${
              requirement.met
                ? "bg-success/15 border-transparent text-success"
                : "bg-text-faint/10 border-transparent text-text-faint"
            }`}
            aria-hidden="true"
          >
            {requirement.met ? "✓" : "✕"}
          </span>

          <span>{requirement.label}</span>
        </li>
      ))}
    </ul>
  );
}