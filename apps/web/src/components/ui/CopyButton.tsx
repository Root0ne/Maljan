"use client";

/* One copy control for a value on a row.
 *
 * The hash rows on IDENTITY and the generated-rule cards on DETECTION each
 * kept their own few lines of the same thing — a button, a clipboard call, a
 * word that flipped to "copied" for a second and a half — and none of them
 * told a screen reader anything had happened, or which of a column of
 * identical "copy" buttons it had pressed. This is the failure note's copy
 * control made general: the name says what is copied, the visible word stays
 * inside that name (WCAG 2.5.3), and the confirmation goes to a polite live
 * region that is rendered before it has anything to say.
 *
 * A clipboard the browser refuses is said in words rather than left as a
 * button that looked pressed and did nothing.
 */

import { useEffect, useRef, useState } from "react";

import { copyToClipboard } from "@/lib/report-utils";
import { copyAnnouncement, copyButtonName, copyButtonText, type CopyState } from "./copyState";

/** How long the confirmation stays before the button reads as itself again. */
const RESET_MS = 1500;

const DEFAULT_CLASS =
  "text-[11px] px-2 py-0.5 border border-border rounded text-text-secondary hover:text-text-primary hover:border-text-muted";

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
  /** The visible word at rest. It must be a word of `what` or "copy", so the
   *  name a voice user reads off the screen is the name the button has. */
  label?: string;
  className?: string;
}) {
  const [state, setState] = useState<CopyState>("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );

  const copy = async () => {
    const ok = await copyToClipboard(value);
    setState(ok ? "copied" : "failed");
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setState("idle"), RESET_MS);
  };

  return (
    <>
      <button
        type="button"
        onClick={() => void copy()}
        aria-label={copyButtonName(state, what)}
        className={className}
      >
        {copyButtonText(state, label)}
      </button>
      <span role="status" className="sr-only">
        {copyAnnouncement(state, what)}
      </span>
    </>
  );
}
