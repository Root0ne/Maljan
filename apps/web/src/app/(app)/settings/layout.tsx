"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { KeyRound, ListChecks, SlidersHorizontal, User } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useAuth } from "@/lib/auth";
import { SettingsProvider, useSettingsContext } from "./configuration/SettingsContext";
import { llmLooksConfigured } from "./setup/status";

interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
}

/** What anyone signed in can change about themselves. */
const ACCOUNT_ITEMS: NavItem[] = [
  { href: "/settings/profile", label: "Profile", icon: User },
  { href: "/settings/api-keys", label: "API keys", icon: KeyRound },
];

const SETUP_ITEM: NavItem = {
  href: "/settings/setup",
  label: "Setup guides",
  icon: ListChecks,
};
const CONSOLE_ITEM: NavItem = {
  href: "/settings/configuration",
  label: "Configuration",
  icon: SlidersHorizontal,
};

/** The two admin areas: the guide hub and the settings console. They share
 *  one `SettingsProvider` so a value staged in a guide is the same staged
 *  value the console and the changes bar show. */
function isAdminArea(pathname: string): boolean {
  return pathname.startsWith("/settings/setup") || pathname.startsWith("/settings/configuration");
}

function Nav({ items, pathname }: { items: NavItem[]; pathname: string }) {
  return (
    <nav aria-label="Settings sections" className="flex border-b border-border mb-6">
      {items.map((item) => {
        const active = pathname.startsWith(item.href);
        const Icon = item.icon;
        return (
          <Link
            key={item.href}
            href={item.href}
            aria-current={active ? "page" : undefined}
            className={`flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium uppercase tracking-wider border-b-2 ${
              active
                ? "border-accent text-accent"
                : "border-transparent text-text-secondary hover:text-text-primary"
            }`}
          >
            <Icon size={16} aria-hidden="true" />
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}

/**
 * The admin's nav, which knows whether there is a model yet.
 *
 * Until one is connected the console is not offered: `/settings/configuration`
 * already bounced to the guides in that state, and a tab that bounces is a tab
 * that lies about where it goes. The guides are the way in, and the console
 * joins them as soon as the analysts have something to talk to.
 */
function AdminNav({ pathname, children }: { pathname: string; children: ReactNode }) {
  const ctx = useSettingsContext();
  const configured = llmLooksConfigured(
    ctx.effectiveValue,
    (key) => ctx.values[key]?.is_set === true,
  );
  const items = [...ACCOUNT_ITEMS, SETUP_ITEM, ...(configured ? [CONSOLE_ITEM] : [])];
  return (
    <>
      <Nav items={items} pathname={pathname} />
      {children}
    </>
  );
}

export default function SettingsLayout({ children }: { children: ReactNode }) {
  const { user: authUser, loading } = useAuth();
  const isAdmin = authUser?.role === "admin";
  const pathname = usePathname() ?? "";

  let body: ReactNode;
  if (isAdmin) {
    // Only an admin mounts the provider at all: a non-admin would spend two
    // requests on a schema the API refuses them, on every settings page.
    body = (
      <SettingsProvider>
        <AdminNav pathname={pathname}>{children}</AdminNav>
      </SettingsProvider>
    );
  } else if (isAdminArea(pathname)) {
    // Each area names itself: a notice under the guides that talks about the
    // Configuration console describes a tab the reader is not on. The tabs
    // themselves are gone rather than disabled — a permanently dead entry on
    // every visit is worse than an entry that is not there.
    const notice = pathname.startsWith("/settings/setup")
      ? "Setup guides are available to administrators only (admin role required)."
      : "Configuration is available to administrators only (admin role required).";
    body = (
      <>
        <Nav items={ACCOUNT_ITEMS} pathname={pathname} />
        {loading ? (
          <div className="text-sm text-text-secondary">Loading…</div>
        ) : (
          <div className="text-sm text-text-secondary" role="alert">
            {notice}
          </div>
        )}
      </>
    );
  } else {
    body = (
      <>
        <Nav items={ACCOUNT_ITEMS} pathname={pathname} />
        {children}
      </>
    );
  }

  return (
    <div>
      <h1 className="text-lg font-semibold text-text-primary mb-1">Settings</h1>
      <p className="text-xs text-text-secondary mb-4">
        Your profile and keys, and the analysis configuration for administrators.
      </p>
      {body}
    </div>
  );
}
