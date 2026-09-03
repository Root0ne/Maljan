"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

const AUTH_DISABLED =
  process.env.NEXT_PUBLIC_AUTH_DISABLED === "true" ||
  process.env.NEXT_PUBLIC_AUTH_DISABLED === "1";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (AUTH_DISABLED) router.replace("/dashboard");
  }, [router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const tokens = await api.login(email, password);
      localStorage.setItem("access_token", tokens.access_token);
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-sm">
      {/* Logo */}
      <div className="flex items-center justify-center mb-8">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--status-blue)" strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />
        </svg>
        <span className="ml-3 text-lg font-semibold text-text-primary tracking-wide">
          MALJAN
        </span>
      </div>

      <div className="bg-bg-surface border border-border rounded p-6">
        <h1 className="text-sm font-medium text-text-primary mb-4">Sign in to your account</h1>

        {error && (
          <div className="mb-4 p-2.5 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label htmlFor="login-email" className="block text-xs text-text-secondary mb-1">Email</label>
            <input
              id="login-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full h-8 px-3 text-xs bg-bg-deep border border-border rounded text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none"
              placeholder="you@example.com"
            />
          </div>
          <div>
            <label htmlFor="login-password" className="block text-xs text-text-secondary mb-1">Password</label>
            <input
              id="login-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full h-8 px-3 text-xs bg-bg-deep border border-border rounded text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none"
              placeholder="Enter password"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full h-8 text-xs font-medium bg-accent text-white rounded hover:bg-accent-hover transition-colors disabled:opacity-50"
          >
            {loading ? "Signing in..." : "Sign in"}
          </button>
        </form>

        <p className="mt-4 text-xs text-text-muted text-center">
          No account?{" "}
          <Link href="/register" className="text-accent-strong hover:underline">
            Register
          </Link>
        </p>
      </div>
    </div>
  );
}
