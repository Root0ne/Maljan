import Link from "next/link";
import CountBadge from "./CountBadge";

/**
 * A row of tabs where each tab is its own URL.
 *
 * Links, not buttons: a tab can be opened in a new window, shared, and
 * reached with the back button, and the page under it is what the URL says.
 * The current tab carries `aria-current="page"`. A count, when given, is
 * drawn as a badge and said as "n items". The row scrolls sideways on a
 * narrow screen instead of wrapping onto a second line.
 */
export interface TabItem {
  key: string;
  label: string;
  href: string;
  count?: number | null;
}

/** The tab `pathname` is on: the longest href that is the path or a parent of it. */
export function activeTabKey(tabs: readonly TabItem[], pathname: string): string | null {
  let best: TabItem | null = null;
  for (const tab of tabs) {
    const hit = pathname === tab.href || pathname.startsWith(`${tab.href}/`);
    if (hit && (!best || tab.href.length > best.href.length)) best = tab;
  }
  return best?.key ?? null;
}

export default function Tabs({
  tabs,
  active,
  label,
}: {
  tabs: readonly TabItem[];
  /** The key of the tab the page is on. */
  active: string | null;
  /** The name of the navigation landmark ("Analysis sections"). */
  label: string;
}) {
  return (
    /* `relative` so the badges' screen-reader text, which is absolutely
     * positioned, is clipped by this scroller instead of widening the page. */
    <nav aria-label={label} className="relative min-w-0 overflow-x-auto">
      <ul className="flex min-w-max items-end gap-1 border-b border-border">
        {tabs.map((tab) => {
          const current = tab.key === active;
          return (
            <li key={tab.key}>
              <Link
                href={tab.href}
                aria-current={current ? "page" : undefined}
                className={`-mb-px flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm ${
                  current
                    ? "border-accent font-medium text-text-primary"
                    : "border-transparent text-text-secondary hover:text-text-primary hover:border-border"
                }`}
              >
                {tab.label}
                {tab.count != null && <CountBadge count={tab.count} label="items" />}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
