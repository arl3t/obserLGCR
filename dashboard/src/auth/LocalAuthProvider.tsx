import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api } from "@/api/client";
import {
  PLATFORM_AUTH_ENABLED,
  SESSION_STORAGE_KEY,
  SESSION_USER_KEY,
} from "@/auth/auth-config";
import { tokenStore } from "@/auth/token-store";

export interface PlatformUser {
  id: string;
  email: string;
  display_name: string | null;
  role: string;
}

interface LocalAuthContextValue {
  token: string | null;
  user: PlatformUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const LocalAuthContext = createContext<LocalAuthContextValue | null>(null);

function decodeJwtExp(token: string): number | null {
  try {
    const part = token.split(".")[1];
    const base64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const payload = JSON.parse(atob(base64)) as { exp?: number };
    return payload.exp ?? null;
  } catch {
    return null;
  }
}

function isTokenValid(token: string | null): boolean {
  if (!token) return false;
  const exp = decodeJwtExp(token);
  if (!exp) return false;
  return exp > Math.floor(Date.now() / 1000) + 60;
}

function loadStoredSession(): { token: string | null; user: PlatformUser | null } {
  try {
    const token = localStorage.getItem(SESSION_STORAGE_KEY);
    const userRaw = localStorage.getItem(SESSION_USER_KEY);
    if (!token || !isTokenValid(token)) {
      localStorage.removeItem(SESSION_STORAGE_KEY);
      localStorage.removeItem(SESSION_USER_KEY);
      return { token: null, user: null };
    }
    const user = userRaw ? (JSON.parse(userRaw) as PlatformUser) : null;
    return { token, user };
  } catch {
    return { token: null, user: null };
  }
}

export function LocalAuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<PlatformUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const stored = loadStoredSession();
    setToken(stored.token);
    setUser(stored.user);
    tokenStore.set(stored.token);
    setIsLoading(false);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    setError(null);
    try {
      const { data } = await api.post<{
        success: boolean;
        token?: string;
        user?: PlatformUser;
        error?: string;
      }>("/api/auth/login", { email, password, expires_in: "8h" });

      if (!data.success || !data.token || !data.user) {
        throw new Error(data.error ?? "Credenciales inválidas");
      }

      localStorage.setItem(SESSION_STORAGE_KEY, data.token);
      localStorage.setItem(SESSION_USER_KEY, JSON.stringify(data.user));
      setToken(data.token);
      setUser(data.user);
      tokenStore.set(data.token);
    } catch (err: unknown) {
      const msg =
        (err as { response?: { data?: { error?: string } } })?.response?.data?.error ??
        (err instanceof Error ? err.message : "Error al iniciar sesión");
      setError(msg);
      throw new Error(msg);
    }
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(SESSION_STORAGE_KEY);
    localStorage.removeItem(SESSION_USER_KEY);
    setToken(null);
    setUser(null);
    tokenStore.clear();
  }, []);

  const value = useMemo<LocalAuthContextValue>(
    () => ({
      token,
      user,
      isAuthenticated: Boolean(token && user),
      isLoading,
      error,
      login,
      logout,
    }),
    [token, user, isLoading, error, login, logout],
  );

  if (!PLATFORM_AUTH_ENABLED) {
    return <>{children}</>;
  }

  return <LocalAuthContext.Provider value={value}>{children}</LocalAuthContext.Provider>;
}

export function useLocalAuth(): LocalAuthContextValue | null {
  return useContext(LocalAuthContext);
}
