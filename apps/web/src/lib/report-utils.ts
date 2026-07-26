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
 * audit 2026-07-26 (T3): `formatDate` existed in four slightly different
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
