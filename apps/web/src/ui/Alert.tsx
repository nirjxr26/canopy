import type { ReactNode } from "react";

type Tone = "error" | "success" | "info";

const TONES: Record<Tone, string> = {
  error: "bg-danger/10 border-danger/35 text-red-300",
  success: "bg-success/10 border-success/35 text-green-300",
  info: "bg-accent/10 border-accent/35 text-indigo-200",
};

export function Alert({ tone, children }: Readonly<{ tone: Tone; children: ReactNode }>) {
  return (
    <div role="alert" className={`flex gap-2.5 p-3 rounded-md border text-[13.5px] mb-4 ${TONES[tone]}`}>
      {children}
    </div>
  );
}
