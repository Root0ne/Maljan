"use client";

import Link from "next/link";
import type { ChangeLine } from "./describeChange";
import { comparableSaved } from "./agentStaging";
import { describeChange } from "./describeChange";
import { groupsBySection, pathForKey } from "./sections";
import { countLabel } from "@/lib/report-utils";
import { APPLIES_SENTENCE } from "./vocabulary";
import type { CatalogEntry, SettingValue, SettingsSchema } from "@/types/settings";

export interface ReviewItem extends ChangeLine {
  hidden: boolean;
  href: string;
  sectionTitle: string;
  groupTitle: string;
  /** Empty when the server accepted this key. */
  errors: string[];
}

/** All validation errors that belong to a staged key: an exact match for a
 *  scalar leaf, or `${key}.<field>` for a composite one (the server map, the
 *  agent definitions, ...) — the same prefix rule the composite editors use
 *  to place a card error. A list rather than one joined sentence: a composite
 *  leaf can be refused on five fields at once, and semicolons between them
 *  made a screen reader recite one run-on paragraph. */
function errorsFor(key: string, errors: Record<string, string>): string[] {
  return Object.entries(errors)
    .filter(([k]) => k === key || k.startsWith(`${key}.`))
    .map(([, v]) => v);
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
    const line = describeChange(
      entriesByKey[key] ?? entry,
      // The stored value in the shape the staged one is sent in: for the agent
      // map those differ, and comparing them raw named five untouched
      // built-ins as changed.
      comparableSaved(key, values[key]?.value),
      pending[key],
    );
    const href = pathForKey(schema, key);
    const titles = titlesByPath.get(href) ?? { sectionTitle: "", groupTitle: "" };
    items.push({
      ...line,
      hidden: hiddenKeys.includes(key),
      href,
      sectionTitle: titles.sectionTitle,
      groupTitle: titles.groupTitle,
      errors: errorsFor(key, errors),
    });
  }
  return items;
}

/** Every field the server refused, across the rows on screen. */
export function reviewErrors(lines: ReviewItem[]): string[] {
  return lines.flatMap((line) => line.errors);
}

/** "3 fields need attention", and the one exception English makes. */
export function attentionLine(count: number): string {
  return `${countLabel(count, "field")} ${count === 1 ? "needs" : "need"} attention`;
}

/**
 * What the server refused, said once and announced once.
 *
 * The messages used to be joined with semicolons into a single `role="alert"`,
 * which a screen reader read as one run-on sentence; splitting them into a
 * list fixed the sentence and lost the announcement, so a reader was told
 * "2 fields need attention" and never which two. The list stays visible and
 * unannounced, and a status node beside it carries the count and the messages
 * politely — one region rather than one per message, which is what produced
 * the run-on in the first place.
 */
export function ReviewErrorSummary({ lines }: { lines: ReviewItem[] }) {
  const messages = reviewErrors(lines);
  return (
    <>
      {messages.length > 0 && (
        <p className="text-xs text-status-red mb-2">{attentionLine(messages.length)}</p>
      )}
      {/* Rendered whether or not there is anything in it. A live region that
          arrives in the DOM together with its first content is announced by
          NVDA and not by VoiceOver; one that is already there when the text
          lands is announced by both. */}
      <p role="status" className="sr-only">
        {messages.length > 0 ? [attentionLine(messages.length), ...messages].join(". ") : ""}
      </p>
    </>
  );
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
                {item.errors.length > 0 && (
                  <ul className="text-xs text-status-red">
                    {item.errors.map((message, i) => (
                      <li key={i}>{message}</li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ul>
  );
}
