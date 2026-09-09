"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { SettingsProvider } from "./configuration/SettingsContext";

const NAV_ITEMS = [
  { href: "/settings/profile", label: "Profile", adminOnly: false },
  { href: "/settings/api-keys", label: "API keys", adminOnly: false },
  { href: "/settings/setup", label: "Setup guides", adminOnly: true },
  { href: "/settings/configuration", label: "Configuration", adminOnly: true },
];

/** The two admin areas: the guide hub and the settings console. They share
 *  one `SettingsProvider` so a value staged in a guide is the same staged
 *  value the console and the changes bar show. */
function isAdminArea(pathname: string): boolean {
  return pathname.startsWith("/settings/setup") || pathname.startsWith("/settings/configuration");
}

export default function SettingsLayout({ children }: { children: ReactNode }) {
  const { user: authUser, loading } = useAuth();
  const isAdmin = authUser?.role === "admin";
  const pathname = usePathname() ?? "";

  let body: ReactNode = children;
  if (isAdmin) {
    // Only an admin mounts the provider at all: a non-admin would spend two
    // requests on a schema the API refuses them, on every settings page.
    body = <SettingsProvider>{children}</SettingsProvider>;
  } else if (isAdminArea(pathname)) {
    body = loading ? (
      <div className="text-sm text-text-secondary">Loading…</div>
    ) : (
      <div className="text-sm text-text-secondary" role="alert">
        Configuration is available to administrators only (admin role required).
      </div>
    );
  }

  return (
    <div>
      <h1 className="text-lg font-semibold text-text-primary mb-1">Settings</h1>
      <p className="text-xs text-text-secondary mb-4">
        Your profile and keys, and the analysis configuration for administrators.
      </p>

      <nav aria-label="Settings sections" className="flex border-b border-border mb-6">
        {NAV_ITEMS.map((item) => {
          const disabled = item.adminOnly && !isAdmin;
          const active = pathname.startsWith(item.href);

          if (disabled) {
            return (
              <span
                key={item.href}
                aria-disabled="true"
                title="Admin role required"
                className="px-4 py-2.5 text-xs font-medium uppercase tracking-wider border-b-2 border-transparent text-text-disabled cursor-not-allowed"
              >
                {item.label}
              </span>
            );
          }

          return (
            <Link
              key={item.href}
              href={item.href}
              aria-current={active ? "page" : undefined}
              className={`px-4 py-2.5 text-xs font-medium uppercase tracking-wider border-b-2 transition-colors ${
                active
                  ? "border-accent text-accent"
                  : "border-transparent text-text-secondary hover:text-text-primary"
              }`}
            >
              {item.label}
            </Link>
          );
        })}
      </nav>

      {body}
    </div>
  );
}
