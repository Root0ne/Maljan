"use client";

import Link from "next/link";
import type { ChangeLine } from "./describeChange";
import { describeChange } from "./describeChange";
import { groupsBySection, pathForKey } from "./sections";
import { APPLIES_SENTENCE } from "./vocabulary";
import type { CatalogEntry, SettingValue, SettingsSchema } from "@/types/settings";

export interface ReviewItem extends ChangeLine {
  hidden: boolean;
  href: string;
  sectionTitle: string;
  groupTitle: string;
  error?: string;
}

/** All validation errors that belong to a staged key: an exact match for a
 *  scalar leaf, or `${key}.<field>` for a composite one (the server map, the
 *  agent definitions, ...) — the same prefix rule the composite editors use
 *  to place a card error. Joined so one review row can show every field the
 *  server rejected. */
function errorFor(key: string, errors: Record<string, string>): string | undefined {
  const matches = Object.entries(errors)
    .filter(([k]) => k === key || k.startsWith(`${key}.`))
    .map(([, v]) => v);
  return matches.length > 0 ? matches.join("; ") : undefined;
}

/** The slice of `SettingsContextValue` `buildReviewItems` reads — named
 *  separately so a test (or another future caller) can hand-build one
 *  without wiring up the whole settings context. `SettingsContextValue`
 *  satisfies this structurally, no cast needed. */
export interface ReviewSource {
  schema: SettingsSchema | null;
  pending: Record<string, unknown>;
  entriesByKey: Record<string, CatalogEntry>;
  values: Record<string, SettingValue>;
  hiddenKeys: string[];
  errors: Record<string, string>;
}

/** Builds one review row per staged key, in schema order, grouped by the
 *  section › group the key's page lives under. Pure and side-effect free —
 *  reused by the setup guides' own review step alongside `ReviewList`. */
export function buildReviewItems(ctx: ReviewSource): ReviewItem[] {
  const { schema, pending, entriesByKey, values, hiddenKeys, errors } = ctx;
  if (!schema) return [];

  const titlesByPath = new Map<string, { sectionTitle: string; groupTitle: string }>();
  for (const { section, groups } of groupsBySection(schema)) {
    for (const group of groups) {
      titlesByPath.set(group.path, { sectionTitle: section.title, groupTitle: group.title });
    }
  }

  const items: ReviewItem[] = [];
  // Schema order (not `Object.keys(pending)` insertion order), so the list
  // reads in the same sequence as the rail regardless of which field the
  // operator touched first.
  for (const entry of schema.groups.flatMap((g) => g.entries)) {
    const key = entry.key;
    if (!(key in pending)) continue;
    const line = describeChange(entriesByKey[key] ?? entry, values[key]?.value, pending[key]);
    const href = pathForKey(schema, key);
    const titles = titlesByPath.get(href) ?? { sectionTitle: "", groupTitle: "" };
    items.push({
      ...line,
      hidden: hiddenKeys.includes(key),
      href,
      sectionTitle: titles.sectionTitle,
      groupTitle: titles.groupTitle,
      error: errorFor(key, errors),
    });
  }
  return items;
}

interface GroupBucket {
  sectionTitle: string;
  groupTitle: string;
  items: ReviewItem[];
}

function bucketByGroup(lines: ReviewItem[]): GroupBucket[] {
  const buckets: GroupBucket[] = [];
  const index = new Map<string, GroupBucket>();
  for (const item of lines) {
    const bucketKey = `${item.sectionTitle} › ${item.groupTitle}`;
    let bucket = index.get(bucketKey);
    if (!bucket) {
      bucket = { sectionTitle: item.sectionTitle, groupTitle: item.groupTitle, items: [] };
      index.set(bucketKey, bucket);
      buckets.push(bucket);
    }
    bucket.items.push(item);
  }
  return buckets;
}

export function ReviewList({ lines }: { lines: ReviewItem[] }) {
  const buckets = bucketByGroup(lines);

  return (
    <ul className="space-y-4">
      {buckets.map((bucket) => (
        <li key={`${bucket.sectionTitle} › ${bucket.groupTitle}`}>
          <h4 className="text-[11px] uppercase tracking-wider text-text-muted mb-1">
            {bucket.sectionTitle} › {bucket.groupTitle}
          </h4>
          <ul className="space-y-2">
            {bucket.items.map((item) => (
              <li key={item.key} className="text-sm text-text-primary">
                <div>
                  <strong>{item.title}</strong> {item.summary}
                  {item.hidden && (
                    <span className="text-text-muted">
                      {" "}
                      (hidden by the current provider selection)
                    </span>
                  )}{" "}
                  <Link href={item.href} className="text-xs text-accent-strong">
                    edit
                  </Link>
                </div>
                {item.detail && item.detail.length > 0 && (
                  <ul className="ml-4 mt-1 space-y-0.5 text-xs text-text-secondary">
                    {item.detail.map((d, i) => (
                      <li key={i}>{d}</li>
                    ))}
                  </ul>
                )}
                <div className="text-xs text-text-muted">
                  <em>{APPLIES_SENTENCE[item.applies]}</em>
                </div>
                {item.error && (
                  <div className="text-xs text-status-red" role="alert">
                    {item.error}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ul>
  );
}
