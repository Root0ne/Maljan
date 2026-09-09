"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { groupsBySection, VIRTUAL_GROUPS, type RailGroup } from "./sections";
import { useSettingsContext } from "./SettingsContext";

function stagedIn(keys: string[], pending: Record<string, unknown>): number {
  return keys.filter((k) => k in pending).length;
}

/** A virtual rail entry counts only the keys it was carved out of its backend
 *  group with, and that backend group's own entry counts the rest — derived
 *  from `VIRTUAL_GROUPS` so adding a split does not need a second edit here. */
function countFor(
  group: RailGroup,
  stagedCountByGroup: Record<string, number>,
  pending: Record<string, unknown>
): number {
  const virtual = VIRTUAL_GROUPS[group.key];
  if (virtual) return stagedIn(virtual.keys, pending);

  const carvedOut = Object.values(VIRTUAL_GROUPS)
    .filter((v) => v.fromGroup === group.key)
    .flatMap((v) => v.keys);
  const own = stagedCountByGroup[group.key] ?? 0;
  return Math.max(0, own - stagedIn(carvedOut, pending));
}

export default function SectionRail() {
  const { schema, stagedCountByGroup, pending } = useSettingsContext();
  const pathname = usePathname();
  const router = useRouter();

  if (!schema) return null;
  const sections = groupsBySection(schema);
  const onGroupRoute = sections.some(({ groups }) => groups.some((g) => g.path === pathname));

  return (
    <>
      <nav
        aria-label="Setting groups"
        data-testid="settings-rail"
        className="hidden lg:block space-y-4"
      >
        {sections.map(({ section, groups }) => (
          <div key={section.key}>
            <h3 className="text-[11px] uppercase tracking-wider text-text-muted px-2 mb-1">
              {section.title}
            </h3>
            <ul className="space-y-0.5">
              {groups.map((group) => {
                const active = pathname === group.path;
                const count = countFor(group, stagedCountByGroup, pending);
                return (
                  <li key={group.key}>
                    <Link
                      href={group.path}
                      aria-current={active ? "page" : undefined}
                      className={`flex items-center justify-between gap-2 px-2 py-1.5 text-xs rounded ${
                        active
                          ? "bg-bg-active text-text-primary"
                          : "text-text-secondary hover:text-text-primary hover:bg-bg-hover"
                      }`}
                    >
                      <span>{group.title}</span>
                      {count > 0 && (
                        <span className="flex items-center justify-center min-w-[1.25rem] h-5 px-1 text-[10px] font-medium rounded-full bg-accent/20 text-accent-strong">
                          <span aria-hidden="true">{count}</span>
                          <span className="sr-only">{count} unsaved changes</span>
                        </span>
                      )}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>
      <div className="lg:hidden mb-4">
        <label htmlFor="settings-group-select" className="sr-only">
          Setting group
        </label>
        <select
          id="settings-group-select"
          aria-label="Setting group"
          value={pathname ?? ""}
          onChange={(e) => router.push(e.target.value)}
          className="w-full bg-bg-deep border border-border rounded px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent"
        >
          {/* The search route is not one of the groups, and without a value to
              match a select shows its first option — naming a group the page
              is not on. Offer a placeholder for that case instead. */}
          {!onGroupRoute && (
            <option value={pathname ?? ""} disabled>
              Jump to a group
            </option>
          )}
          {sections.flatMap(({ section, groups }) =>
            groups.map((group) => (
              <option key={group.path} value={group.path}>
                {section.title} › {group.title}
              </option>
            ))
          )}
        </select>
      </div>
    </>
  );
}
