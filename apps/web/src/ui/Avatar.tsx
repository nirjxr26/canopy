interface AvatarProps {
  name?: string | null;
  email?: string | null;
  size?: number;
  className?: string;
}

function initialsFor(name: string | null | undefined, email: string | null | undefined): string {
  if (name !== null && name !== undefined) {
    const parts = name.trim().split(/\s+/);
    const first = parts[0]?.[0] ?? "";
    const last = parts.length > 1 ? (parts.at(-1)?.[0] ?? "") : "";
    return `${first}${last}`.toUpperCase();
  }
  if (email !== null && email !== undefined) {
    return email[0]?.toUpperCase() ?? "";
  }
  return "";
}

export function displayName(firstName: string | null | undefined, lastName: string | null | undefined): string | null {
  const parts = [firstName, lastName].filter((p): p is string => p !== null && p !== undefined && p !== "");
  return parts.length > 0 ? parts.join(" ") : null;
}

export function Avatar({ name, email, size = 36, className }: Readonly<AvatarProps>) {
  const initials = initialsFor(name, email);

  return (
    <span
      className={`inline-flex items-center justify-center rounded-full bg-bg-elevated border border-border-strong text-text-muted font-semibold select-none ${className ?? ""}`}
      style={{ width: size, height: size, fontSize: size * 0.4 }}
      aria-hidden={initials === ""}
    >
      {initials}
    </span>
  );
}
