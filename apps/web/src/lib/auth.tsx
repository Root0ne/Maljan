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

/* ── Auth bypass (local dev) ───────────────────────────── */

const AUTH_DISABLED =
  process.env.NEXT_PUBLIC_AUTH_DISABLED === "true" ||
  process.env.NEXT_PUBLIC_AUTH_DISABLED === "1";

const DEV_USER: AuthUser = {
  id: "00000000-0000-0000-0000-000000000001",
  email: "dev@local",
  full_name: "Dev User",
  role: "admin",
};

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
  const [user, setUser] = useState<AuthUser | null>(AUTH_DISABLED ? DEV_USER : null);
  const [loading, setLoading] = useState(!AUTH_DISABLED);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Wave 10 W10-LINT-DEBT-02 (2026-05-30): cycle-break refs so
  // ``startRefreshTimer`` and ``logout`` can reference one another
  // without tripping React Compiler's access-before-declared rule.
  // Both functions are declared once; the refs are populated by the
  // mount-time effect below and reused by every subsequent call.
  const startRefreshTimerRef = useRef<((token: string) => void) | null>(null);
  const logoutRef = useRef<(() => void) | null>(null);

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
          // Chain next refresh through the ref so we always read the
          // latest closure (a future dep change on startRefreshTimer
          // would otherwise leave this site bound to the original).
          refreshTimerRef.current = scheduleRefresh(
            refresh,
            (t) => startRefreshTimerRef.current?.(t),
            () => logoutRef.current?.(),
          );
        },
        () => logoutRef.current?.(),
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
    if (AUTH_DISABLED) return;
    // Wave 10 W10-LINT-DEBT-02: mount-time session hydration. fetchUser
    // sets ``user`` + ``loading`` based on the result of an async API
    // call; there is no derived-state alternative because the value
    // depends on server-side session state, not props.
    fetchUser();
    const refreshToken = localStorage.getItem("refresh_token");
    if (refreshToken) {
      startRefreshTimer(refreshToken);
    }
    return () => clearRefreshTimer();
  }, [fetchUser, startRefreshTimer, clearRefreshTimer]);

  useEffect(() => {
    if (AUTH_DISABLED) return;
    if (!loading && user === null) {
      router.push("/login");
    }
  }, [loading, user, router]);

  const login = async (email: string, password: string) => {
    if (AUTH_DISABLED) {
      setUser(DEV_USER);
      return;
    }
    const tokens = await api.login(email, password);
    localStorage.setItem("access_token", tokens.access_token);
    localStorage.setItem("refresh_token", tokens.refresh_token);
    startRefreshTimer(tokens.refresh_token);
    await fetchUser();
  };

  const register = async (email: string, password: string, full_name: string) => {
    if (AUTH_DISABLED) {
      setUser(DEV_USER);
      return;
    }
    await api.register(email, password, full_name);
    await login(email, password);
  };

  const logout = useCallback(() => {
    if (AUTH_DISABLED) {
      // Auth is disabled — logout is a no-op; keep the dev user logged in.
      return;
    }
    clearRefreshTimer();
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    setUser(null);
    window.location.href = "/login";
  }, [clearRefreshTimer]);

  // Wave 10 W10-LINT-DEBT-02 (2026-05-30): sync the cycle-break refs
  // after both functions are constructed. Runs once per render so
  // ``startRefreshTimer``'s closures always invoke the current
  // ``logout`` / ``startRefreshTimer`` rather than stale captures.
  useEffect(() => {
    startRefreshTimerRef.current = startRefreshTimer;
    logoutRef.current = logout;
  }, [startRefreshTimer, logout]);

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
