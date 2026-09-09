"use client";

import { useState } from "react";
import type { McpServerEntry } from "@/types/settings";
import { mapKeyError } from "../../configuration/mapEditorHelpers";
import {
  EMPTY_SERVER,
  RESERVED_SERVER_KEYS,
  ServerDetail,
  useServerProbe,
} from "../../configuration/ServerMapEditor";
import { useSettingsContext } from "../../configuration/SettingsContext";
import { stateString, type GuideStepProps } from "./types";

const SERVERS_KEY = "core.mcp.servers";
/** The radio value that means "not one of the existing servers". A space
 *  cannot collide with a server key, which the key rule keeps to a slug. */
const NEW_SERVER = " new";

export const SERVER_STEP_SECTIONS = ["connection", "tools", "agents"] as const;
export type ServerStepSection = (typeof SERVER_STEP_SECTIONS)[number];

/** The section a guide step asked for, or the first one when it named
 *  nothing this component draws. */
export function serverStepSection(section: string | undefined): ServerStepSection {
  return (SERVER_STEP_SECTIONS as readonly string[]).includes(section ?? "")
    ? (section as ServerStepSection)
    : "connection";
}

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

/**
 * One section of the console's server form, for the server this guide is
 * building.
 *
 * The guide's first step has to say *which* server before any of the fields
 * mean anything, so this component carries that chooser itself: until
 * `state.serverKey` names one, it offers the servers already configured plus
 * a name box for a new one, under the same key rules the console's "Add
 * server" applies. Everything after that is `ServerDetail` — the same fields,
 * the same staging into `core.mcp.servers`, the same probe.
 */
export default function ServerFormStep({
  section,
  state,
  setState,
}: GuideStepProps & { section: ServerStepSection }) {
  const ctx = useSettingsContext();
  const entry = ctx.entriesByKey[SERVERS_KEY];
  const value = (ctx.pending[SERVERS_KEY] ??
    ctx.values[SERVERS_KEY]?.value ??
    entry?.default ??
    {}) as Record<string, McpServerEntry>;

  const chosen = stateString(state, "serverKey");
  const serverKey = chosen !== null && chosen in value ? chosen : null;
  const probe = useServerProbe(serverKey, value);

  const [choice, setChoice] = useState<string>("");
  const [newKey, setNewKey] = useState("");
  const [keyError, setKeyError] = useState<string | null>(null);

  if (!entry) {
    return <p role="alert">The tool-server map is not in the catalog.</p>;
  }

  const pick = () => {
    if (choice !== NEW_SERVER) {
      if (choice === "") {
        setKeyError("pick a server, or name a new one");
        return;
      }
      setKeyError(null);
      setState({ serverKey: choice });
      return;
    }
    const key = newKey.trim();
    const problem = mapKeyError(key, value, "server", RESERVED_SERVER_KEYS);
    if (problem) {
      setKeyError(problem);
      return;
    }
    setKeyError(null);
    // The new server exists in the staged map from here on, exactly as the
    // console's "Add server" creates it, so every later step edits a server
    // that is already part of what Apply will send.
    ctx.stage(SERVERS_KEY, { ...value, [key]: { ...EMPTY_SERVER } });
    setState({ serverKey: key });
  };

  if (serverKey === null) {
    const keys = Object.keys(value);
    return (
      <fieldset className="border-0 p-0 m-0" data-testid="server-chooser">
        <legend className="sr-only">Which tool server</legend>
        <div className="space-y-2">
          {keys.map((key) => (
            <label key={key} className="flex gap-2 items-center text-sm text-text-primary">
              <input
                type="radio"
                name="guide-server"
                value={key}
                checked={choice === key}
                onChange={() => setChoice(key)}
              />
              <span className="font-mono">{key}</span>
              <span className="text-xs text-text-secondary">
                {value[key].transport}
                {value[key].enabled ? "" : " (disabled)"}
              </span>
            </label>
          ))}
          <label className="flex gap-2 items-center text-sm text-text-primary">
            <input
              type="radio"
              name="guide-server"
              value={NEW_SERVER}
              checked={choice === NEW_SERVER}
              onChange={() => setChoice(NEW_SERVER)}
            />
            New server
          </label>
          <input
            className={input}
            placeholder="new server name"
            aria-label="new server name"
            value={newKey}
            onChange={(e) => {
              setNewKey(e.target.value);
              setChoice(NEW_SERVER);
            }}
          />
        </div>
        <div className="flex items-center gap-3 mt-2">
          <button type="button" className="text-xs text-accent-strong" onClick={pick}>
            Use this server
          </button>
          {keyError && (
            <span className="text-[11px] text-status-red" role="alert">
              {keyError}
            </span>
          )}
        </div>
      </fieldset>
    );
  }

  return (
    <div>
      <p className="text-xs text-text-secondary mb-2">
        Editing <span className="font-mono text-text-primary">{serverKey}</span>{" "}
        <button
          type="button"
          className="text-[11px] text-accent-strong"
          onClick={() => setState({ serverKey: null })}
        >
          Choose a different server
        </button>
      </p>
      <ServerDetail
        serverKey={serverKey}
        value={value}
        onChange={(v) => ctx.stage(SERVERS_KEY, v)}
        probe={probe}
        errors={ctx.errors}
        entryKey={SERVERS_KEY}
        editable={entry.editable}
        sections={[section]}
      />
    </div>
  );
}
