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
  /** Set when the session could not be *checked* — distinct from `user: null`,
   *  which means the session was checked and there isn't one. */
  authError: string | null;
  retryAuth: () => void;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, full_name: string) => Promise<void>;
  logout: () => void;
}

/**
 * Did this failure actually mean "your session is not valid"?
 *
 * `ApiClient` throws exactly this message on a 401 (and on the 403 the backend
 * returns for a missing credential); everything else — a connection refusal, a
 * CORS rejection, a 500, a timeout — arrives as some other Error. Treating the
 * two alike is how a thirty-second backend restart used to log every open tab
 * out and destroy its refresh token, and it is also what turned a mocked-CORS
 * preflight failure in the WebKit E2E run into an unexplained bounce to /login.
 */
function isSessionRejection(error: unknown): boolean {
  return error instanceof Error && error.message === "Unauthorized";
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
  const [authError, setAuthError] = useState<string | null>(null);
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
    setAuthError(null);
    try {
      const me = await api.getMe();
      setUser(me);
    } catch (err) {
      if (isSessionRejection(err)) {
        // The server looked at the credential and refused it. Clearing is
        // correct; the guard effect below then sends the user to /login.
        localStorage.removeItem("access_token");
        localStorage.removeItem("refresh_token");
        setUser(null);
      } else {
        // We never got an answer. The session may well still be valid, so keep
        // the tokens and say what happened instead of silently signing out.
        setAuthError(
          err instanceof Error ? err.message : "Could not reach the server"
        );
      }
    } finally {
      setLoading(false);
    }
  }, []);

  const retryAuth = useCallback(() => {
    setLoading(true);
    setAuthError(null);
    void fetchUser();
  }, [fetchUser]);

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
    // `authError` means the check never completed, so `user === null` carries no
    // information about the session. Redirecting here would present a login
    // screen as the diagnosis for what is really a server outage — and, worse,
    // it looks identical to a genuine expiry, so nobody reports the outage.
    if (authError) return;
    if (!loading && user === null) {
      router.push("/login");
    }
  }, [loading, user, authError, router]);

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
    <AuthContext.Provider
      value={{ user, loading, authError, retryAuth, login, register, logout }}
    >
      {authError ? <SessionCheckFailed error={authError} onRetry={retryAuth} /> : children}
    </AuthContext.Provider>
  );
}

/**
 * Shown when the session could not be verified.
 *
 * Deliberately replaces `children` rather than sitting above them: with `user`
 * null but the session possibly fine, every page below would render its
 * signed-out shape and fire its own doomed requests, producing a screenful of
 * unrelated errors instead of the one that matters.
 */
function SessionCheckFailed({
  error,
  onRetry,
}: {
  error: string;
  onRetry: () => void;
}) {
  return (
    <div
      role="alert"
      className="min-h-screen flex items-center justify-center p-6"
    >
      <div className="max-w-md w-full bg-bg-surface border border-status-red/20 rounded p-5 space-y-3">
        <h1 className="text-sm font-medium text-status-red">
          Could not reach the server
        </h1>
        <p className="text-sm text-text-muted leading-relaxed">
          Your session could not be verified because the API did not respond.
          You have <strong>not</strong> been signed out — this is a connection
          problem, not an expired login.
        </p>
        <p className="text-xs text-text-muted font-mono break-all">{error}</p>
        <button
          type="button"
          onClick={onRetry}
          className="text-sm px-3 py-1.5 border border-border rounded hover:bg-bg-surface"
        >
          Try again
        </button>
      </div>
    </div>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
