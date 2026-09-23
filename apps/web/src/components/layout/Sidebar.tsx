"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { ClipboardList, FileSearch, LayoutDashboard, ScrollText, Settings } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useAuth } from "@/lib/auth";

interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
}

/* Four destinations, because there are four things to do here: see how the
 * platform is running, hold samples, read the analyses of them, and change how
 * they are analysed. "Reports" was a fifth that led to the analyses already
 * listed under Jobs, filtered to the finished ones. */
const BASE_NAV_ITEMS: NavItem[] = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/samples", label: "Samples", icon: FileSearch },
  { href: "/jobs", label: "Analyses", icon: ClipboardList },
  { href: "/settings", label: "Settings", icon: Settings },
];

const ADMIN_NAV_ITEM: NavItem = {
  href: "/audit",
  label: "Audit Logs",
  icon: ScrollText,
};

export default function Sidebar() {
  const pathname = usePathname();
  const [expanded, setExpanded] = useState(false);
  const { user } = useAuth();

  const navItems = user?.role === "admin"
    ? [...BASE_NAV_ITEMS, ADMIN_NAV_ITEM]
    : BASE_NAV_ITEMS;

  return (
    <aside
      onMouseEnter={() => setExpanded(true)}
      onMouseLeave={() => setExpanded(false)}
      className="fixed left-0 top-0 h-full z-40 flex flex-col border-r border-border bg-bg-surface transition-[width] duration-200 print:hidden"
      style={{ width: expanded ? "var(--sidebar-expanded)" : "var(--sidebar-width)" }}
    >
      {/* Logo */}
      <div className="flex items-center h-12 px-2.5 border-b border-border">
        {/* The mark is a static SVG in public/; next/image would route it
            through the image optimizer, which refuses SVG by default. */}
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img src="/logo.svg" alt="Maljan" width={27} height={28} />
        {expanded && (
          <span className="ml-3 text-sm font-semibold text-text-primary tracking-wide">
            MALJAN
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-2" aria-label="Primary">
        {navItems.map((item) => {
          const active = pathname.startsWith(item.href);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              // The label span is hidden while the rail is collapsed, leaving an
              // icon-only link with no discernible name (Lighthouse link-name).
              // aria-label keeps every nav item named in both states; title adds
              // a hover tooltip for the collapsed rail.
              aria-label={item.label}
              title={item.label}
              aria-current={active ? "page" : undefined}
              className={`flex items-center h-10 px-3.5 mx-1 my-0.5 rounded text-sm ${
                active
                  ? "bg-bg-active text-text-primary"
                  : "text-text-secondary hover:text-text-primary hover:bg-bg-hover"
              }`}
            >
              <Icon size={18} aria-hidden="true" className="flex-shrink-0" />
              {expanded && (
                <span className="ml-3 truncate">{item.label}</span>
              )}
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
