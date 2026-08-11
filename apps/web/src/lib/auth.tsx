import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { authApi, ApiError, type User } from "./api";

const USER_STORAGE_KEY = "auuth.user";

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  login(email: string, password: string, persistent?: boolean): Promise<{ user: User } | { mfaRequired: true; mfaToken: string }>;
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

export function AuthProvider({ children }: { readonly children: ReactNode }) {
  const [user, setUser] = useState<User | null>(() => readStoredUser());
  const [loading, setLoading] = useState(true);

  const updateUser = useCallback((next: User | null) => {
    setUser(next);
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
        if (!cancelled) updateUser(current);
      })
      .catch(() => {
        if (!cancelled) updateUser(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [updateUser]);

  const login = useCallback(
    async (email: string, password: string, persistent: boolean = true) => {
      const result = await authApi.login({ email, password, persistent });
      if ("mfaRequired" in result) {
        return result;
      }
      updateUser(result.user);
      return result;
    },
    [updateUser],
  );

  const signup = useCallback(
    async (input: { email: string; password: string; firstName?: string; lastName?: string }) => {
      const result = await authApi.signup(input);
      updateUser(result.user);
      return result;
    },
    [updateUser],
  );

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 401) {
        throw error;
      }
    }
    updateUser(null);
  }, [updateUser]);

  const refresh = useCallback(async () => {
    try {
      const { user: current } = await authApi.me();
      updateUser(current);
      return current;
    } catch {
      updateUser(null);
      return null;
    }
  }, [updateUser]);

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
