import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { authApi, ApiError, type User } from "./api";

const USER_STORAGE_KEY = "auuth.user";

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login(email: string, password: string): Promise<{ user: User } | { mfaRequired: true; mfaToken: string }>;
  signup(
    input: { email: string; password: string; firstName?: string; lastName?: string },
  ): Promise<{ user: User; devEmailLink?: string }>;
  logout(): Promise<void>;
  refresh(): Promise<User | null>;
  setUser(user: User | null): void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function readStoredUser(): User | null {
  try {
    const raw = localStorage.getItem(USER_STORAGE_KEY);
    return raw ? (JSON.parse(raw) as User) : null;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUserState] = useState<User | null>(() => readStoredUser());
  const [loading, setLoading] = useState(true);

  const setUser = useCallback((next: User | null) => {
    setUserState(next);
    if (next === null) {
      localStorage.removeItem(USER_STORAGE_KEY);
    } else {
      localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(next));
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    authApi
      .me()
      .then(({ user: current }) => {
        if (!cancelled) setUser(current);
      })
      .catch(() => {
        if (!cancelled) setUser(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [setUser]);

  const login = useCallback(
    async (email: string, password: string) => {
      const result = await authApi.login({ email, password });
      if ("mfaRequired" in result) {
        return result;
      }
      setUser(result.user);
      return result;
    },
    [setUser],
  );

  const signup = useCallback(
    async (input: { email: string; password: string; firstName?: string; lastName?: string }) => {
      const result = await authApi.signup(input);
      setUser(result.user);
      return result;
    },
    [setUser],
  );

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 401) {
        throw error;
      }
    }
    setUser(null);
  }, [setUser]);

  const refresh = useCallback(async () => {
    try {
      const { user: current } = await authApi.me();
      setUser(current);
      return current;
    } catch {
      setUser(null);
      return null;
    }
  }, [setUser]);

  const value = useMemo<AuthContextValue>(
    () => ({ user, loading, login, signup, logout, refresh, setUser }),
    [user, loading, login, signup, logout, refresh, setUser],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (context === null) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
