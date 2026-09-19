/* Shared helpers for the malware-report tabs.
 *
 * Keep this small and dependency-free; if it grows beyond formatting +
 * download glue, split it. The download helpers are deliberately
 * imperative (browser-only) — they create a temporary <a> tag, click it,
 * and revoke the object URL synchronously.
 */

export function downloadBlob(content: string, filename: string, mime: string): void {
  downloadObject(new Blob([content], { type: mime }), filename);
}

/** Save an already-built Blob (PDF and other binary exports). */
export function downloadObject(blob: Blob, filename: string): void {
  if (typeof window === "undefined") return;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // F14 (2026-07-05): defer revocation. Revoking synchronously right after
  // click() aborts the download in some browsers (Firefox/Safari) because
  // the URL is freed before the browser has started fetching the blob.
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export function copyToClipboard(text: string): Promise<boolean> {
  if (typeof navigator === "undefined" || !navigator.clipboard) {
    return Promise.resolve(false);
  }
  return navigator.clipboard
    .writeText(text)
    .then(() => true)
    .catch(() => false);
}

/* ── Time / duration formatting ─────────────────────────
 *
 * `formatDate` existed in four slightly different
 * shapes and `formatDuration` in three, so the same timestamp rendered
 * differently on every page. These are the single canonical implementations;
 * every page imports from here.
 */

/** Canonical absolute timestamp, e.g. "Jul 5, 2026, 07:34 PM". */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "Never";
  return new Date(iso).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** Canonical elapsed duration: "N/A", "42s", or "3m 07s" (seconds zero-padded). */
export function formatDuration(seconds: number | null | undefined): string {
  if (!seconds) return "N/A";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${String(s).padStart(2, "0")}s`;
}

/** Canonical relative timestamp, e.g. "just now" / "12m ago" / "3d ago". */
export function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function formatBytes(bytes: number): string {
  if (!bytes || bytes < 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = bytes;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit++;
  }
  const fixed = unit === 0 ? size.toFixed(0) : size.toFixed(2);
  return `${fixed} ${units[unit]}`;
}

export function entropyClass(entropy: number): string {
  if (entropy >= 7.0) return "text-status-red";
  if (entropy >= 6.0) return "text-status-orange";
  if (entropy >= 4.0) return "text-status-blue";
  return "text-text-secondary";
}

export function confidenceClass(confidence: number): string {
  const c = confidence > 1 ? confidence / 100 : confidence;
  if (c >= 0.75) return "text-status-red";
  if (c >= 0.45) return "text-status-orange";
  return "text-status-green";
}

export function confidenceBarColor(confidence: number): string {
  const c = confidence > 1 ? confidence / 100 : confidence;
  if (c >= 0.75) return "bg-status-red";
  if (c >= 0.45) return "bg-status-orange";
  return "bg-status-green";
}

export function truncateMiddle(value: string, max = 32): string {
  if (!value) return "";
  if (value.length <= max) return value;
  const head = Math.ceil((max - 1) / 2);
  const tail = Math.floor((max - 1) / 2);
  return `${value.slice(0, head)}…${value.slice(value.length - tail)}`;
}

/**
 * "1 result", "2 results" — a count and its noun, agreeing.
 *
 * Every list header used to hard-code the plural, so a
 * filter that matched one job announced "1 RESULTS". The irregular plurals
 * ("entry" -> "entries") are why the plural form is a parameter rather than an
 * appended "s".
 */
export function countLabel(
  count: number,
  singular: string,
  plural = `${singular}s`,
): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

/**
 * What the exported STIX bundle lost, as one sentence, or null.
 *
 * Built from the reasons, never from the total. `integrity_objects_removed`
 * counts both integrity passes, and the second one runs after the indicator
 * cap and removes nothing but relationships the cap orphaned — so on the very
 * shape this sentence exists for, "6 objects repaired away as malformed or
 * duplicated" was six relationships that were neither. Each reason is named
 * with its own count: what the pass repaired, what the cap orphaned, what the
 * cap removed, and the references a report or a note lost without any object
 * leaving.
 *
 * Null when nothing was removed, so a clean run says nothing rather than
 * saying zero, and null for a stored run written before the counters existed.
 */
interface TruncationCounts {
  evidence_corpus_missing_answers?: number;
  evidence_corpus_missing_tools?: string[];
  evidence_corpus_partial_reason?: string;
  evidence_corpus_answers?: number;
  evidence_corpus_bytes_held?: number;
  evidence_corpus_bytes_ceiling?: number;
  integrity_objects_removed?: number;
  indicator_cap_removed?: number;
  integrity_refs_trimmed?: number;
  integrity_dropped?: Record<string, number>;
}

export function bundleLossSentence(truncation: TruncationCounts | null): string | null {
  const dropped = truncation?.integrity_dropped ?? {};
  const count = (value: unknown) => Math.max(0, Number(value ?? 0) || 0);

  // The pass's own repairs: everything it removed except what it swept up
  // after the cap, which is the cap's loss and is named as such below.
  const orphaned = count(dropped.cap_orphan);
  const repaired = Math.max(0, count(truncation?.integrity_objects_removed) - orphaned);
  const capped = count(truncation?.indicator_cap_removed);
  const refs = count(truncation?.integrity_refs_trimmed);

  const parts: string[] = [];
  if (repaired > 0) {
    parts.push(`${countLabel(repaired, "object")} repaired away as malformed or duplicated`);
  }
  if (capped > 0) {
    parts.push(
      `${countLabel(capped, "indicator")} over the export's total cap, lowest priority first`,
    );
  }
  if (orphaned > 0) {
    parts.push(`${countLabel(orphaned, "relationship")} left pointing at a capped indicator`);
  }
  if (refs > 0) {
    parts.push(`${countLabel(refs, "reference")} trimmed from a report or a note`);
  }
  if (parts.length === 0) return null;
  return `The exported STIX bundle is shorter than what the run produced: ${parts.join("; ")}.`;
}

/**
 * What the run's grounding could not search, as one sentence, or null.
 *
 * A run whose corpus could not hold everything states every absence as a note
 * and drops nothing for it. Said here because the alternative is an operator
 * reading it inside one finding's message, and because such a run otherwise
 * looks exactly like one whose grounding was whole.
 *
 * Null when the grounding searched the whole record, and null for a run stored
 * before the counters existed.
 */
/**
 * Past this share of the ceiling the figures are printed unasked: a corpus
 * holding more than half of what it may hold is one whose ceiling is a number
 * the operator should know before the run that reaches it.
 */
const CORPUS_LOUD_SHARE = 0.5;

/**
 * What the run's grounding corpus held, as one sentence, or null.
 *
 * Printed only where it tells a reader something: a corpus that went partial,
 * with the loss stated beside it, or one past half its ceiling. Null for a run
 * that recorded nothing about what it held — which is not a corpus that held
 * nothing — and null for one with room to spare, whose figures stay on the
 * record unsaid.
 *
 * The report says the same thing in the same words
 * (`analysis/run_summary.corpus_held_sentence`).
 */
export function corpusHeldSentence(truncation: TruncationCounts | null): string | null {
  const answers = truncation?.evidence_corpus_answers;
  const held = truncation?.evidence_corpus_bytes_held;
  const ceiling = truncation?.evidence_corpus_bytes_ceiling;
  if (answers == null || held == null || ceiling == null) return null;
  const partial = (truncation?.evidence_corpus_partial_reason ?? "").trim() !== "";
  if (!partial && !(ceiling > 0 && held > ceiling * CORPUS_LOUD_SHARE)) return null;
  return `The grounding corpus held ${countLabel(answers, "answer")}, ${held} of ${ceiling} bytes.`;
}

export function partialGroundingSentence(truncation: TruncationCounts | null): string | null {
  const reason = (truncation?.evidence_corpus_partial_reason ?? "").trim();
  if (!reason) return null;
  const missing = Math.max(0, Number(truncation?.evidence_corpus_missing_answers ?? 0) || 0);
  const tools = (truncation?.evidence_corpus_missing_tools ?? []).filter(Boolean);
  const named = tools.length > 0 ? `, from ${tools.join(", ")}` : "";
  return (
    `Grounding searched less than the run produced — ${reason}: ` +
    `${countLabel(missing, "answer")} not kept${named}. ` +
    `An absence measured against it is a note and drops nothing.`
  );
}
