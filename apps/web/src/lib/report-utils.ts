/* Shared helpers for the malware-report tabs.
 *
 * Keep this small and dependency-free; if it grows beyond formatting +
 * download glue, split it. The download helpers are deliberately
 * imperative (browser-only) — they create a temporary <a> tag, click it,
 * and revoke the object URL synchronously.
 */

export function downloadBlob(content: string, filename: string, mime: string): void {
  if (typeof window === "undefined") return;
  const blob = new Blob([content], { type: mime });
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
