"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth";

const NAV_ITEMS = [
  { href: "/settings/profile", label: "Profile", adminOnly: false },
  { href: "/settings/api-keys", label: "API keys", adminOnly: false },
  // The setup-guide hub does not exist yet; Task 16 restores this entry.
  { href: "/settings/configuration", label: "Configuration", adminOnly: true },
];

export default function SettingsLayout({ children }: { children: ReactNode }) {
  const { user: authUser } = useAuth();
  const isAdmin = authUser?.role === "admin";
  const pathname = usePathname();

  return (
    <div>
      <h1 className="text-lg font-semibold text-text-primary mb-1">Settings</h1>
      <p className="text-xs text-text-secondary mb-4">
        Your profile and keys, and the analysis configuration for administrators.
      </p>

      <nav aria-label="Settings sections" className="flex border-b border-border mb-6">
        {NAV_ITEMS.map((item) => {
          const disabled = item.adminOnly && !isAdmin;
          const active = pathname?.startsWith(item.href) ?? false;

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

      {children}
    </div>
  );
}
