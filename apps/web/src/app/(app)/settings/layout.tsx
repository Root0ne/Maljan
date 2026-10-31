"use client";

import type { ReactNode } from "react";
import { usePathname } from "next/navigation";
import Tabs, { activeTabKey } from "@/components/ui/Tabs";
import { useAuth } from "@/lib/auth";
import { SettingsProvider, useSettingsContext } from "./configuration/SettingsContext";
import { llmLooksConfigured } from "./setup/status";

interface NavItem {
  href: string;
  label: string;
}

/** What anyone signed in can change about themselves. */
const ACCOUNT_ITEMS: NavItem[] = [
  { href: "/settings/profile", label: "Profile" },
  { href: "/settings/api-keys", label: "API keys" },
];

const SETUP_ITEM: NavItem = {
  href: "/settings/setup",
  label: "Setup guides",
};
const CONSOLE_ITEM: NavItem = {
  href: "/settings/configuration",
  label: "Configuration",
};

/** The two admin areas: the guide hub and the settings console. They share
 *  one `SettingsProvider` so a value staged in a guide is the same staged
 *  value the console and the changes bar show. */
function isAdminArea(pathname: string): boolean {
  return pathname.startsWith("/settings/setup") || pathname.startsWith("/settings/configuration");
}

/** The settings' sections as the console's tab row (`ui/Tabs`), each its own URL. */
function Nav({ items, pathname }: { items: NavItem[]; pathname: string }) {
  const tabs = items.map((item) => ({ key: item.href, label: item.label, href: item.href }));
  return (
    <div className="mb-6">
      <Tabs tabs={tabs} active={activeTabKey(tabs, pathname)} label="Settings sections" />
    </div>
  );
}

/**
 * The admin's nav, which knows whether there is a model yet.
 *
 * Until one is connected the console is not offered: `/settings/configuration`
 * already bounced to the guides in that state, and a tab that bounces is a tab
 * that lies about where it goes. The guides are the way in, and the console
 * joins them as soon as the analysts have something to talk to.
 *
 * It is the provider's `chrome`, so it survives a schema that is still
 * loading, refused or broken — the way back to a profile page does not depend
 * on a catalogue.
 */
function AdminNav({ pathname }: { pathname: string }) {
  const ctx = useSettingsContext();
  const configured = llmLooksConfigured(
    ctx.effectiveValue,
    (key) => ctx.values[key]?.is_set === true,
    ctx.schema,
  );
  const items = [...ACCOUNT_ITEMS, SETUP_ITEM, ...(configured ? [CONSOLE_ITEM] : [])];
  return <Nav items={items} pathname={pathname} />;
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
      <SettingsProvider chrome={<AdminNav pathname={pathname} />}>{children}</SettingsProvider>
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
