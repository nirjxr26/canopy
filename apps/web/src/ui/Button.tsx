import { forwardRef, type ButtonHTMLAttributes } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "ghost";
  loading?: boolean;
  block?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "primary", loading = false, block = false, disabled, children, className, type = "button", ...rest },
  ref,
) {
  const baseClasses = "inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-md border border-transparent text-sm font-semibold cursor-pointer transition-all disabled:opacity-55 disabled:cursor-not-allowed";
  
  const variantClasses = variant === "primary"
    ? "bg-accent text-accent-contrast hover:bg-accent-hover"
    : "bg-transparent text-accent hover:bg-accent/10 px-3 py-2 font-medium";

  const blockClasses = block ? "w-full" : "";

  const combinedClasses = `${baseClasses} ${variantClasses} ${blockClasses} ${className ?? ""}`.trim();

  return (
    <button
      ref={ref}
      type={type}
      className={combinedClasses}
      disabled={disabled || loading}
      aria-busy={loading}
      {...rest}
    >
      {loading ? (
        <span
          className="w-4 h-4 border-2 border-white/35 border-t-current rounded-full animate-spin"
          aria-hidden="true"
        />
      ) : null}
      {children}
    </button>
  );
});
