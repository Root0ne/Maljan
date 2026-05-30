"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

export default function RegisterPage() {
  const router = useRouter();
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await api.register(email, password, fullName);
      const tokens = await api.login(email, password);
      localStorage.setItem("access_token", tokens.access_token);
      localStorage.setItem("refresh_token", tokens.refresh_token);
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-sm">
      <div className="flex items-center justify-center mb-8">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--status-blue)" strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />
        </svg>
        <span className="ml-3 text-lg font-semibold text-text-primary tracking-wide">MALJAN</span>
      </div>

      <div className="bg-bg-surface border border-border rounded p-6">
        <h1 className="text-sm font-medium text-text-primary mb-4">Create an account</h1>

        {error && (
          <div className="mb-4 p-2.5 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="block text-xs text-text-secondary mb-1">Full name</label>
            <input
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              required
              className="w-full h-8 px-3 text-xs bg-bg-deep border border-border rounded text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
              placeholder="John Doe"
            />
          </div>
          <div>
            <label className="block text-xs text-text-secondary mb-1">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full h-8 px-3 text-xs bg-bg-deep border border-border rounded text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
              placeholder="you@example.com"
            />
          </div>
          <div>
            <label className="block text-xs text-text-secondary mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
              className="w-full h-8 px-3 text-xs bg-bg-deep border border-border rounded text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
              placeholder="Min 8 characters"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full h-8 text-xs font-medium bg-accent text-white rounded hover:bg-accent-hover transition-colors disabled:opacity-50"
          >
            {loading ? "Creating account..." : "Create account"}
          </button>
        </form>

        <p className="mt-4 text-xs text-text-muted text-center">
          Already have an account?{" "}
          <Link href="/login" className="text-accent-strong hover:underline">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}
