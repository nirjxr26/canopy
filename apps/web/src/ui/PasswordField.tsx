import { useId, useState, type InputHTMLAttributes } from "react";

interface PasswordFieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  error?: string | null;
  hint?: string;
}

export function PasswordField({ label, error, hint, id, className, ...rest }: PasswordFieldProps) {
  const autoId = useId();
  const inputId = id ?? autoId;
  const toggleId = useId();
  const [visible, setVisible] = useState(false);
  
  const baseInputClasses = "w-full pl-3 pr-10 py-2.5 bg-bg-elevated border border-border rounded-md text-text text-sm placeholder:text-text-faint outline-none transition";
  const errorInputClasses = error ? "border-danger" : "";
  const combinedInputClasses = `${baseInputClasses} ${errorInputClasses} ${className ?? ""}`.trim();

  return (
    <div className="flex flex-col gap-1.5 mb-4">
      <label className="text-xs font-medium text-text" htmlFor={inputId}>
        {label}
      </label>
      <div className="relative flex items-center">
        <input
          id={inputId}
          className={combinedInputClasses}
          type={visible ? "text" : "password"}
          aria-invalid={error ? true : undefined}
          {...rest}
        />
        <button
          id={toggleId}
          type="button"
          className="absolute right-2.5 top-1/2 -translate-y-1/2 p-1 flex items-center justify-center bg-transparent border-0 rounded-md text-text-faint cursor-pointer focus:outline-none shrink-0"
          aria-label={visible ? "Hide password" : "Show password"}
          onClick={() => setVisible((v) => !v)}
        >
          {visible ? (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
              <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
              <path d="M14.12 14.12a3 3 0 1 1-4.24-4.24" />
              <line x1="1" y1="1" x2="23" y2="23" />
            </svg>
          ) : (
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z" />
              <circle cx="12" cy="12" r="3" />
            </svg>
          )}
        </button>
      </div>
      {hint && !error ? <span className="text-[12.5px] text-text-faint">{hint}</span> : null}
      {error ? <span className="text-[12.5px] text-danger">{error}</span> : null}
    </div>
  );
}
