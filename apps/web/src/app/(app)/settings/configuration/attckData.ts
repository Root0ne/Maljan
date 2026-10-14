/**
 * The sentences the ATT&CK cache panel shows, from what the worker answered.
 *
 * Kept apart from the component so each wording rule is tested on its own: a
 * failed check is never "up to date", the dialog names both versions and the
 * release date, and waiting names the date of the next automatic check (or
 * says there is none).
 */

import { formatDateTime } from "@/lib/report-utils";
import type {
  AttckCaller,
  AttckCheckResult,
  AttckDomainStatus,
  AttckStatus,
  AttckUpdateResult,
} from "@/types/settings";

/** The setting the panel sits under, in the "Analysis layers" group. */
export const ATTCK_REFRESH_KEY = "core.validation.attck_refresh_days";

/** How often an update in progress is asked about, in milliseconds. */
export const UPDATE_POLL_MS = 2000;

export function ageLabel(days: number | undefined): string {
  if (days === undefined || days === null) return "";
  if (days < 1) return "less than a day";
  const whole = Math.floor(days);
  return whole === 1 ? "1 day" : `${whole} days`;
}

/** A release date as MITRE stamps it, shown as a date. */
export function releaseDate(iso: string | undefined | null): string {
  if (!iso) return "";
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return iso;
  return at.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

export interface StatusRow {
  domain: string;
  label: string;
  version: string;
  released: string;
  cachedAt: string;
  age: string;
  nextCheck: string;
}

export function statusRows(status: AttckStatus): StatusRow[] {
  return status.domains.map((d: AttckDomainStatus) => {
    if (!d.present) {
      return {
        domain: d.domain,
        label: d.label,
        version: "not cached",
        released: "",
        cachedAt: "",
        age: "",
        nextCheck: "",
      };
    }
    return {
      domain: d.domain,
      label: d.label,
      version: d.readable === false ? "unreadable" : d.version || "unknown",
      released: releaseDate(d.released),
      cachedAt: d.cached_at ? formatDateTime(d.cached_at) : "",
      age: ageLabel(d.age_days),
      nextCheck: d.next_check_at
        ? formatDateTime(d.next_check_at)
        : status.refresh_days > 0
          ? ""
          : "off",
    };
  });
}

/** When the cache will next be compared with MITRE on its own. */
export function nextCheckSentence(refreshDays: number | null | undefined, nextCheckAt: string | null): string {
  if (!refreshDays || refreshDays <= 0) {
    return "Automatic checks are off (the interval is 0): the cache changes only when it is updated here.";
  }
  if (!nextCheckAt) {
    return "The automatic check is due now and runs within the hour.";
  }
  return `The next automatic check is due on ${formatDateTime(nextCheckAt)}.`;
}

function who(caller: AttckCaller | undefined, trigger: string | undefined): string {
  if (trigger === "schedule") return "the automatic check";
  return caller?.name || "an administrator";
}

export type CheckView =
  | { kind: "up_to_date"; text: string }
  | { kind: "outdated"; rows: { label: string; cached: string; latest: string; released: string }[] }
  | { kind: "failed"; text: string };

export function readCheck(result: AttckCheckResult): CheckView {
  if (result.outcome === "failed" || !result.ok) {
    return {
      kind: "failed",
      text:
        `The check failed: ${result.reason || "no reason was given"}. ` +
        "Whether a newer release exists is not known, and the cache was not changed.",
    };
  }
  if (result.outcome === "outdated") {
    return {
      kind: "outdated",
      rows: result.domains
        .filter((d) => d.state === "outdated" || d.state === "missing")
        .map((d) => ({
          label: d.label,
          cached: d.cached.present ? d.cached.version || "unknown" : "not cached",
          latest: d.latest?.version ?? "",
          released: releaseDate(d.latest?.released),
        })),
    };
  }
  const listed = result.domains
    .filter((d) => d.state !== "unlisted")
    .map((d) => `${d.label} ${d.cached.version}`);
  const unlisted = result.domains.filter((d) => d.state === "unlisted").map((d) => d.label);
  return {
    kind: "up_to_date",
    text:
      `Up to date: ${listed.join(", ")}.` +
      (unlisted.length ? ` Not listed by MITRE: ${unlisted.join(", ")}.` : ""),
  };
}

/** What choosing to wait means, in a sentence. */
export function waitSentence(result: AttckCheckResult): string {
  const kept = result.domains
    .filter((d) => d.state === "outdated" || d.state === "missing")
    .map((d) => `${d.label} ${d.cached.present ? d.cached.version : "(not cached)"}`)
    .join(", ");
  if (!result.refresh_days || result.refresh_days <= 0) {
    return `The cache stays at ${kept}. Automatic checks are off, so it changes only when it is updated here.`;
  }
  if (!result.next_check_at) {
    return `The cache stays at ${kept} until the automatic check, which is due now and runs within the hour.`;
  }
  return `The cache stays at ${kept} until the automatic check on ${formatDateTime(result.next_check_at)}.`;
}

export function lastCheckLine(check: AttckCheckResult | null): string {
  if (!check) return "Last check: never.";
  const when = formatDateTime(check.checked_at);
  const by = who(check.triggered_by, undefined);
  if (check.outcome === "failed" || !check.ok) {
    return `Last check: ${when} by ${by}, failed: ${check.reason}.`;
  }
  if (check.outcome === "outdated") {
    return `Last check: ${when} by ${by}, a newer release was available.`;
  }
  return `Last check: ${when} by ${by}, up to date.`;
}

function changesText(result: AttckUpdateResult): string {
  return result.changes
    .map((c) => `${c.label} ${c.from || "(not cached)"} → ${c.to}`)
    .join(", ");
}

export function lastUpdateLine(update: AttckUpdateResult | null): string {
  if (!update) return "Last update: never.";
  const when = formatDateTime(update.finished_at ?? update.started_at);
  const by = who(update.triggered_by, update.trigger);
  if (!update.ok) {
    return `Last update: ${when} by ${by}, failed: ${update.reason}. The previous cache was kept.`;
  }
  if (!update.changes.length) {
    return `Last update: ${when} by ${by}, every domain was already current.`;
  }
  return `Last update: ${when} by ${by}, ${changesText(update)}.`;
}

/** The sentence an update ends with. */
export function updateOutcome(result: AttckUpdateResult): { ok: boolean; text: string } {
  if (!result.ok) {
    return {
      ok: false,
      text: `The update failed: ${result.reason}. The previous cache is unchanged.`,
    };
  }
  if (!result.changes.length) {
    return { ok: true, text: "Every domain was already current; nothing was downloaded." };
  }
  return {
    ok: true,
    text:
      `Updated: ${changesText(result)}. The previous files are kept as a backup. ` +
      "Analyses already running keep the catalogue they loaded; the next analysis reads the new one.",
  };
}
