import { useCallback, useState } from "react";
import { ApiError } from "./api";

export function messageFrom(error: unknown): string {
  if (error instanceof ApiError) {
    // Surface the correlation id so users/support can match failures to server logs (plan §9).
    return error.requestId !== "" ? `${error.message} (Ref: ${error.requestId})` : error.message;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return "Something went wrong. Please try again.";
}

export interface SubmitState {
  pending: boolean;
  error: string | null;
}

export function useSubmit() {
  const [state, setState] = useState<SubmitState>({ pending: false, error: null });

  const run = useCallback(async (fn: () => Promise<void>) => {
    setState({ pending: true, error: null });
    try {
      await fn();
      setState({ pending: false, error: null });
    } catch (error) {
      setState({ pending: false, error: messageFrom(error) });
    }
  }, []);

  return { ...state, run, setError: (error: string | null) => setState((s) => ({ ...s, error })) };
}
