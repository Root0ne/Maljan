"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import type { McpServerEntry, VirustotalRegistration } from "@/types/settings";
import { useSettingsContext } from "../../configuration/SettingsContext";
import type { GuideStepProps } from "./types";

const SERVERS_KEY = "core.mcp.servers";
export const VIRUSTOTAL_KEY = "virustotal";

/** What a registration costs and what it grants, in the operator's own terms.
 *  Kept next to the button rather than in the documentation, because the
 *  choice it describes is made here. */
export const QUOTA_NOTE =
  "The agent token is free and is issued to this deployment without an account. " +
  "VirusTotal enforces its own published quotas on it; a lookup over quota comes " +
  "back as a 429 with a retry delay, and the analyst carries on without that answer.";

export const SUBMIT_NOTE =
  "Only the read-only lookups are ticked. The submit tools upload the sample itself " +
  "to VirusTotal, where it is shared with their customers, so they stay off until " +
  "you tick them in the Tools step.";

/**
 * The "Connect VirusTotal" step: one button that registers this deployment.
 *
 * Registration is a server-side write, not a staged edit — the token it
 * returns is stored encrypted before the browser hears about it, so this step
 * does not go through the guide's Apply. The button reports what came back:
 * the public handle VirusTotal now knows this deployment by, and the state of
 * the server it just enabled.
 */
export default function VirustotalStep({ state, setState }: GuideStepProps) {
  const ctx = useSettingsContext();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const registered = state.virustotal as VirustotalRegistration | undefined;

  const servers = (ctx.values[SERVERS_KEY]?.value ?? {}) as Record<string, McpServerEntry>;
  const stored = servers[VIRUSTOTAL_KEY];
  const alreadySet = stored?.auth_token_source === "ui";

  const register = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await api.registerVirustotal();
      setState({ virustotal: result });
      // The write happened on the server, so the console's own copy of the
      // settings is now behind: re-reading is what makes the Tools step show
      // the server as enabled rather than as it was before the button.
      await ctx.reload();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-2">
      <p className="text-xs text-text-secondary">{QUOTA_NOTE}</p>
      <p className="text-xs text-text-secondary">{SUBMIT_NOTE}</p>
      {alreadySet && !registered && (
        <p className="text-[11px] text-text-muted" role="status">
          This deployment already has an agent token. Registering again replaces it.
        </p>
      )}
      <div className="flex items-center gap-3">
        <button
          type="button"
          className="text-xs text-accent-strong disabled:opacity-50"
          disabled={busy}
          onClick={() => void register()}
        >
          {busy ? "Registering…" : "Register"}
        </button>
        {registered && (
          <span className="text-[11px] text-status-green" role="status">
            registered as {registered.public_handle || registered.agent_id} ·{" "}
            {registered.url} · token stored
          </span>
        )}
        {error && (
          <span className="text-[11px] text-status-red" role="alert">
            {error}
          </span>
        )}
      </div>
    </div>
  );
}
