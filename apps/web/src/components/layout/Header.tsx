"use client";

import { useAuth } from "@/lib/auth";

export default function Header() {
  const { user, logout } = useAuth();

  return (
    <header className="h-12 flex items-center justify-between px-4 border-b border-border bg-bg-surface">
      {/* Search */}
      <div className="flex items-center flex-1 max-w-2xl">
        <div className="relative w-full">
          <svg
            className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted"
            width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
          >
            <circle cx="11" cy="11" r="8" />
            <path d="m21 21-4.35-4.35" />
          </svg>
          <input
            type="text"
            placeholder="Search for files, hashes, IPs, or malware families..."
            className="w-full h-8 pl-9 pr-3 text-xs bg-bg-deep border border-border rounded text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
          />
        </div>
      </div>

      {/* User */}
      <div className="flex items-center gap-3 ml-4">
        {user && (
          <>
            <span className="text-xs text-text-secondary">{user.email}</span>
            <button
              onClick={logout}
              className="text-xs text-text-muted hover:text-text-primary transition-colors"
            >
              Sign out
            </button>
          </>
        )}
      </div>
    </header>
  );
}
