"use client";

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
  type ReactNode,
} from "react";
import { useRouter } from "next/navigation";
import { api } from "./api";

interface AuthUser {
  id: string;
  email: string;
  full_name: string;
  role: string;
}

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, full_name: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/* ── JWT helpers ───────────────────────────────────────── */

function decodeJwtExpiry(token: string): number | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const decoded = JSON.parse(atob(payload));
    return typeof decoded.exp === "number" ? decoded.exp * 1000 : null;
  } catch {
    return null;
  }
}

function scheduleRefresh(
  refreshToken: string,
  onSuccess: (access: string, refresh: string) => void,
  onFailure: () => void
): ReturnType<typeof setTimeout> {
  const expiry = decodeJwtExpiry(refreshToken);
  const msUntilExpiry = expiry ? expiry - Date.now() : 14 * 60 * 1000; // default 14 min
  const msBefore = Math.max(msUntilExpiry - 60_000, 5_000); // refresh 60s before expiry, min 5s

  return setTimeout(async () => {
    try {
      const tokens = await api.refresh(refreshToken);
      localStorage.setItem("access_token", tokens.access_token);
      localStorage.setItem("refresh_token", tokens.refresh_token);
      onSuccess(tokens.access_token, tokens.refresh_token);
    } catch {
      onFailure();
    }
  }, msBefore);
}

/* ── Provider ──────────────────────────────────────────── */

export function AuthProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearRefreshTimer = useCallback(() => {
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }
  }, []);

  const startRefreshTimer = useCallback(
    (refreshToken: string) => {
      clearRefreshTimer();
      refreshTimerRef.current = scheduleRefresh(
        refreshToken,
        (_access, refresh) => {
          // Chain next refresh
          refreshTimerRef.current = scheduleRefresh(refresh, startRefreshTimer, logout);
        },
        logout
      );
    },
    [clearRefreshTimer]
  );

  const fetchUser = useCallback(async () => {
    const token = localStorage.getItem("access_token");
    if (!token) {
      setLoading(false);
      return;
    }
    try {
      const me = await api.getMe();
      setUser(me);
    } catch {
      localStorage.removeItem("access_token");
      localStorage.removeItem("refresh_token");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUser();
    const refreshToken = localStorage.getItem("refresh_token");
    if (refreshToken) {
      startRefreshTimer(refreshToken);
    }
    return () => clearRefreshTimer();
  }, [fetchUser, startRefreshTimer, clearRefreshTimer]);

  useEffect(() => {
    if (!loading && user === null) {
      router.push("/login");
    }
  }, [loading, user, router]);

  const login = async (email: string, password: string) => {
    const tokens = await api.login(email, password);
    localStorage.setItem("access_token", tokens.access_token);
    localStorage.setItem("refresh_token", tokens.refresh_token);
    startRefreshTimer(tokens.refresh_token);
    await fetchUser();
  };

  const register = async (email: string, password: string, full_name: string) => {
    await api.register(email, password, full_name);
    await login(email, password);
  };

  const logout = useCallback(() => {
    clearRefreshTimer();
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    setUser(null);
    window.location.href = "/login";
  }, [clearRefreshTimer]);

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
