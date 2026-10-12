"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import type { CredentialBootstrapResult, McpServerEntry } from "@/types/settings";
import { useSettingsContext } from "../../configuration/SettingsContext";
import type { GuideStepProps } from "./types";

const SERVERS_KEY = "core.mcp.servers";

/** Where the guide keeps what one server's request answered. */
export function credentialStateKey(server: string): string {
  return `credential:${server}`;
}

/** The line shown once the credential is stored: the first of the answer's
 *  declared facts that is not empty (the name the service now knows this
 *  deployment by; a declaration lists them in the order it prefers), the
 *  server's address, and that the token is stored. */
export function obtainedLine(result: CredentialBootstrapResult): string {
  const name = Object.values(result.facts ?? {}).find((v) => v !== "");
  const parts = name ? [`registered as ${name}`] : [];
  if (result.url) parts.push(result.url);
  parts.push("token stored");
  return parts.join(" · ");
}

/**
 * The "obtain a credential" step of any tool server that declares
 * `credential_bootstrap`: one button that performs the declared request.
 *
 * It is a server-side write, not a staged edit — the credential it returns
 * is stored encrypted before the browser hears about it, so this step does
 * not go through the guide's Apply. The button reports what came back: the
 * names the service now knows this deployment by, and the state of the
 * server it just enabled.
 */
export default function CredentialStep({
  server,
  note,
  state,
  setState,
}: GuideStepProps & { server: string; note?: string }) {
  const ctx = useSettingsContext();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const obtained = state[credentialStateKey(server)] as CredentialBootstrapResult | undefined;

  const servers = (ctx.values[SERVERS_KEY]?.value ?? {}) as Record<string, McpServerEntry>;
  const alreadySet = servers[server]?.auth_token_source === "ui";

  const obtain = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await api.obtainServerCredential(server);
      setState({ [credentialStateKey(server)]: result });
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
      {note && <p className="text-xs text-text-secondary">{note}</p>}
      {alreadySet && !obtained && (
        <p className="text-[11px] text-text-muted" role="status">
          This server already has a stored credential. Obtaining a new one replaces it.
        </p>
      )}
      <div className="flex items-center gap-3">
        <button
          type="button"
          className="text-xs text-accent-strong disabled:opacity-50"
          disabled={busy}
          onClick={() => void obtain()}
        >
          {busy ? "Obtaining…" : "Obtain credential"}
        </button>
        {obtained && (
          <span className="text-[11px] text-status-green" role="status">
            {obtainedLine(obtained)}
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
