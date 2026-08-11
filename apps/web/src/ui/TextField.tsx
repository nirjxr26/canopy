import { useId, type InputHTMLAttributes } from "react";

interface TextFieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  error?: string | null;
  hint?: string;
}

export function TextField({ label, error, hint, id, className, ...rest }: TextFieldProps) {
  const autoId = useId();
  const inputId = id ?? autoId;
  
  const baseInputClasses = "w-full px-3 py-2.5 bg-bg-elevated border border-border rounded-md text-text text-sm placeholder:text-text-faint outline-none transition";
  const errorInputClasses = error ? "border-danger" : "";
  const combinedInputClasses = `${baseInputClasses} ${errorInputClasses} ${className ?? ""}`.trim();

  return (
    <div className="flex flex-col gap-1.5 mb-4">
      <label className="text-xs font-medium text-text" htmlFor={inputId}>
        {label}
      </label>
      <input id={inputId} className={combinedInputClasses} aria-invalid={error ? true : undefined} {...rest} />
      {hint && !error ? <span className="text-[12.5px] text-text-faint">{hint}</span> : null}
      {error ? <span className="text-[12.5px] text-danger">{error}</span> : null}
    </div>
  );
}
