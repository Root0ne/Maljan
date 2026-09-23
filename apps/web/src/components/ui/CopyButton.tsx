"use client";

/* One copy control for a value on a row.
 *
 * The hash rows on IDENTITY and the generated-rule cards on DETECTION each
 * kept their own few lines of the same thing — a button, a clipboard call, a
 * word that flipped to "copied" for a second and a half — and none of them
 * told a screen reader anything had happened, or which of a column of
 * identical "copy" buttons it had pressed. This is the failure note's copy
 * control made general: the name says what is copied, holds the visible word
 * (WCAG 2.5.3) and stays the same under focus, and the one announcement goes
 * to a polite live region that is rendered before it has anything to say.
 * The "Copied" a sighted reader sees sits beside the button and is hidden
 * from the accessibility tree, so it is not read a second time.
 *
 * A clipboard the browser refuses is said in words rather than left as a
 * button that looked pressed and did nothing. A second press within the
 * confirmation's lifetime clears the region first, so it is announced again.
 */

import { useEffect, useRef, useState } from "react";

import { copyToClipboard } from "@/lib/report-utils";
import { copyAnnouncement, copyButtonName, copyConfirmation, type CopyState } from "./copyState";

/** How long the confirmation stays before the control reads as itself again. */
const RESET_MS = 1500;

/** The colour of the sighted confirmation; the word is always printed. */
const CONFIRMATION_CLASS: Record<CopyState, string> = {
  idle: "",
  copied: "text-status-green",
  failed: "text-status-red",
};

/* At least 24 px tall (WCAG 2.5.8), whatever the text size. */
const DEFAULT_CLASS =
  "inline-flex min-h-6 items-center text-[11px] px-2 py-0.5 border border-border rounded text-text-secondary hover:text-text-primary hover:border-text-muted";

export default function CopyButton({
  value,
  what,
  label = "copy",
  className = DEFAULT_CLASS,
}: {
  /** What goes on the clipboard. */
  value: string;
  /** What is being copied, for the name and the announcement — "SHA-256 of
   *  invoice.exe" names the button "Copy SHA-256 of invoice.exe". */
  what: string;
  /** The visible word. It must be a word of `what` or "copy", so the name a
   *  voice user reads off the screen is the name the button has. */
  label?: string;
  className?: string;
}) {
  const [state, setState] = useState<CopyState>("idle");
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const copy = async () => {
    const ok = await copyToClipboard(value);
    timers.current.forEach(clearTimeout);
    // Empty first, so the same sentence twice is still a change to announce.
    setState("idle");
    timers.current = [
      setTimeout(() => setState(ok ? "copied" : "failed"), 50),
      setTimeout(() => setState("idle"), 50 + RESET_MS),
    ];
  };

  return (
    <span className="inline-flex items-center gap-1.5">
      <button
        type="button"
        onClick={() => void copy()}
        aria-label={copyButtonName(what)}
        className={className}
      >
        {label}
      </button>
      {state !== "idle" && (
        <span
          aria-hidden="true"
          className={`text-[11px] ${CONFIRMATION_CLASS[state]}`}
        >
          {copyConfirmation(state)}
        </span>
      )}
      <span role="status" className="sr-only">
        {copyAnnouncement(state, what)}
      </span>
    </span>
  );
}
