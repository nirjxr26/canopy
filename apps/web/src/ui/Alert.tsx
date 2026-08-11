import type { ReactNode } from "react";

type Tone = "error" | "success" | "info";

const TONES: Record<Tone, string> = {
  error: "alert--error",
  success: "alert--success",
  info: "alert--info",
};

export function Alert({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <div className={`alert ${TONES[tone]}`}>{children}</div>;
}
