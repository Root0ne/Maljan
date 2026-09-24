"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { ContextWindow } from "@/types/settings";
import { contextWindowNote } from "./contextWindowNote";

/** The catalog key this note belongs to, named once so both sides agree. */
export const TOOL_OUTPUT_KEY = "core.preprocessing.max_tool_output_chars";

/**
 * What the served model's context window is, beside the setting it decides.
 *
 * Read once per mount from the read-only endpoint. The request costs no
 * tokens — it reads a server's metadata endpoint and never asks a model to
 * produce anything — and the API caches the answer per provider, endpoint and
 * model, so opening the page repeatedly asks the endpoint once.
 *
 * A failure is silent by design: this is context beside a field, not the
 * field, and a settings page that showed an error banner because a model
 * server was down would be reporting the wrong problem in the wrong place.
 */
export default function ContextWindowNote() {
  /* Not named `window`: this is a client component, and shadowing the global
     inside one is a trap for the next reader of the effect below. */
  const [detected, setDetected] = useState<ContextWindow | null>(null);

  useEffect(() => {
    let live = true;
    api
      .getContextWindow()
      .then((w) => {
        if (live) setDetected(w);
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, []);

  if (!detected) return null;
  return (
    <p className="text-xs text-text-secondary mt-1" data-testid="context-window-note">
      {contextWindowNote(detected)}
    </p>
  );
}
