"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import type { CatalogEntry, McpServerEntry, ProbeResult, SettingValue } from "@/types/settings";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

/** Built-ins are re-seeded by the settings model, so they disable rather than delete. */
const BUILTIN = new Set(["network", "threatintel"]);
const ROLES = ["static", "dynamic", "network", "judge"] as const;
const SLUG = /^[a-z][a-z0-9_-]{0,31}$/;
/** What a set token looks like from outside; identical to the API's mask. */
const TOKEN_MASK = "**********";

const TOKEN_SOURCE_LABEL: Record<string, string> = {
  ui: "set from the UI",
  env: "set in .env",
  default: "not set",
};

export const EMPTY_SERVER: McpServerEntry = {
  enabled: true,
  transport: "stdio",
  command: "",
  args: [],
  env: {},
  cwd: "",
  env_allow: [],
  url: "",
  auth_token: "",
  auth_token_source: "default",
  tool_selection: "dynamic",
  use_all_tools: false,
  // A new server exposes nothing until its tools are ticked off a probe.
  tools: [],
  agents: [],
  label: "",
};

/**
 * The whole `core.mcp.servers` leaf, as a list of cards.
 *
 * One staged value for the whole map, not one per card: the PATCH body is the
 * full dict, so the apply bar, the hidden-dirty count and the reset behaviour
 * from sub-project A all apply unchanged, and a half-applied map — three
 * servers saved and the fourth rejected — cannot happen.
 *
 * The token field rides inside that same dict and behaves the way `SecretWidget`
 * behaves everywhere else: what arrives is the mask (or an empty string), the
 * input is a password field that only appears once the operator asks to edit,
 * an untouched card sends the mask straight back and the API reads that as
 * "leave the stored row alone", and "Clear" stages `null`. The value the
 * operator types exists only in this component's state until it is applied;
 * it never comes back from a GET.
 */
export default function ServerMapEditor({
  entry,
  current,
  staged,
  onChange,
}: {
  entry: CatalogEntry;
  current: SettingValue | undefined;
  staged: unknown;
  onChange: (value: Record<string, McpServerEntry>) => void;
}) {
  const value = (staged ?? current?.value ?? entry.default ?? {}) as Record<string, McpServerEntry>;
  const [newKey, setNewKey] = useState("");
  const [keyError, setKeyError] = useState<string | null>(null);
  const [probes, setProbes] = useState<Record<string, ProbeResult | "running">>({});
  /** Which cards have their token field open for editing. A card is closed
   *  until the operator asks, so a masked value cannot be typed over by
   *  accident and cannot be read back by looking at the form. */
  const [editingToken, setEditingToken] = useState<Record<string, boolean>>({});

  const put = (key: string, next: Partial<McpServerEntry>) =>
    onChange({ ...value, [key]: { ...value[key], ...next } });

  const add = () => {
    const key = newKey.trim();
    if (!SLUG.test(key)) {
      setKeyError("lowercase, starts with a letter, at most 32 of a-z 0-9 - _");
      return;
    }
    if (key in value) {
      setKeyError("a server with that name already exists");
      return;
    }
    setKeyError(null);
    setNewKey("");
    onChange({ ...value, [key]: { ...EMPTY_SERVER } });
  };

  const remove = (key: string) => {
    if (BUILTIN.has(key)) {
      put(key, { enabled: false });
      return;
    }
    const next = { ...value };
    delete next[key];
    onChange(next);
  };

  const probe = async (key: string) => {
    setProbes((p) => ({ ...p, [key]: "running" }));
    try {
      const result = await api.testMcpServer(key, { "core.mcp.servers": value });
      setProbes((p) => ({ ...p, [key]: result }));
    } catch (e) {
      setProbes((p) => ({
        ...p,
        [key]: { ok: false, latency_ms: 0, detail: getErrorMessage(e), models: null, tools: null },
      }));
    }
  };

  return (
    <div className="space-y-3" data-testid="server-map-editor">
      {Object.entries(value).map(([key, server]) => {
        const result = probes[key];
        const manifest = result && result !== "running" ? result.tools : null;
        const allowed = server.tools;
        return (
          <div key={key} className="border border-border rounded p-3" data-server={key}>
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="text-sm text-text-primary font-mono">{key}</span>
              <div className="flex items-center gap-3">
                <label className="text-xs text-text-secondary flex items-center gap-1">
                  <input
                    type="checkbox"
                    aria-label={`${key} enabled`}
                    checked={server.enabled}
                    onChange={(e) => put(key, { enabled: e.target.checked })}
                  />
                  enabled
                </label>
                <button
                  type="button"
                  className="text-xs text-accent-strong disabled:opacity-50"
                  disabled={result === "running"}
                  onClick={() => void probe(key)}
                >
                  Test
                </button>
                <button
                  type="button"
                  className="text-xs text-text-secondary"
                  onClick={() => remove(key)}
                >
                  {BUILTIN.has(key) ? "Disable" : "Remove"}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <label className="block">
                <span className="text-text-muted">Label</span>
                <input
                  className={input}
                  aria-label={`${key} label`}
                  value={server.label}
                  onChange={(e) => put(key, { label: e.target.value })}
                />
              </label>
              <label className="block">
                <span className="text-text-muted">Transport</span>
                <select
                  className={input}
                  aria-label={`${key} transport`}
                  value={server.transport}
                  onChange={(e) => put(key, { transport: e.target.value })}
                >
                  {["stdio", "http", "streamable-http", "sse"].map((t) => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </label>
              {server.transport === "stdio" ? (
                <>
                  <label className="block">
                    <span className="text-text-muted">Command</span>
                    <input
                      className={input}
                      aria-label={`${key} command`}
                      value={server.command}
                      onChange={(e) => put(key, { command: e.target.value })}
                    />
                  </label>
                  <label className="block">
                    <span className="text-text-muted">Arguments (one per line)</span>
                    <textarea
                      className={input}
                      rows={2}
                      aria-label={`${key} args`}
                      value={server.args.join("\n")}
                      onChange={(e) =>
                        put(key, { args: e.target.value.split("\n").filter((a) => a !== "") })
                      }
                    />
                  </label>
                  <label className="block">
                    <span className="text-text-muted">Working directory</span>
                    <input
                      className={input}
                      aria-label={`${key} cwd`}
                      value={server.cwd}
                      onChange={(e) => put(key, { cwd: e.target.value })}
                    />
                  </label>
                  <label className="block">
                    <span className="text-text-muted">
                      Environment names passed through (one per line)
                    </span>
                    <textarea
                      className={input}
                      rows={2}
                      aria-label={`${key} env allow`}
                      value={server.env_allow.join("\n")}
                      onChange={(e) =>
                        put(key, { env_allow: e.target.value.split("\n").filter((a) => a !== "") })
                      }
                    />
                  </label>
                </>
              ) : (
                <>
                  <label className="block">
                    <span className="text-text-muted">URL</span>
                    <input
                      className={input}
                      aria-label={`${key} url`}
                      value={server.url}
                      onChange={(e) => put(key, { url: e.target.value })}
                    />
                  </label>
                  <div className="block">
                    <span className="text-text-muted">Auth token</span>
                    {editingToken[key] ? (
                      <input
                        type="password"
                        className={input}
                        aria-label={`${key} auth token`}
                        autoComplete="new-password"
                        value={server.auth_token === TOKEN_MASK ? "" : server.auth_token}
                        onChange={(e) => put(key, { auth_token: e.target.value })}
                      />
                    ) : (
                      <p className="text-text-secondary py-1.5" data-token-state={key}>
                        {TOKEN_SOURCE_LABEL[server.auth_token_source] ?? "not set"}
                      </p>
                    )}
                    <div className="flex gap-3 mt-1">
                      <button
                        type="button"
                        className="text-[11px] text-accent-strong"
                        onClick={() => {
                          if (editingToken[key]) {
                            // Closing the field abandons whatever was typed and
                            // puts the mask back, which the API reads as
                            // "leave the stored token alone".
                            put(key, {
                              auth_token:
                                server.auth_token_source === "default" ? "" : TOKEN_MASK,
                            });
                          }
                          setEditingToken((t) => ({ ...t, [key]: !t[key] }));
                        }}
                      >
                        {editingToken[key] ? "Keep current" : "Replace token"}
                      </button>
                      {server.auth_token_source !== "default" && (
                        <button
                          type="button"
                          className="text-[11px] text-text-secondary"
                          aria-label={`${key} clear auth token`}
                          onClick={() => {
                            // `null` is how every secret in this project is
                            // cleared: the API deletes the row rather than
                            // storing an empty one.
                            put(key, { auth_token: null as unknown as string });
                            setEditingToken((t) => ({ ...t, [key]: false }));
                          }}
                        >
                          Clear
                        </button>
                      )}
                    </div>
                  </div>
                </>
              )}
            </div>

            <fieldset className="mt-2">
              <legend className="text-xs text-text-muted">Agents</legend>
              <div className="flex gap-3 flex-wrap">
                {ROLES.map((role) => (
                  <label key={role} className="text-xs text-text-secondary flex items-center gap-1">
                    <input
                      type="checkbox"
                      aria-label={`${key} agent ${role}`}
                      checked={server.agents.includes(role)}
                      onChange={(e) =>
                        put(key, {
                          agents: e.target.checked
                            ? [...server.agents, role]
                            : server.agents.filter((r) => r !== role),
                        })
                      }
                    />
                    {role}
                  </label>
                ))}
              </div>
            </fieldset>

            {result === "running" && (
              <p className="text-[11px] text-text-muted mt-2">testing…</p>
            )}
            {result && result !== "running" && (
              <p
                className={`text-[11px] mt-2 ${result.ok ? "text-status-green" : "text-status-red"}`}
                role="status"
              >
                {result.ok ? "ok" : "failed"} · {result.latency_ms} ms · {result.detail}
              </p>
            )}
            {manifest && manifest.length > 0 && (
              <fieldset className="mt-2">
                <legend className="text-xs text-text-muted">
                  Tools the model may call ({allowed === null ? "all" : allowed.length} of{" "}
                  {manifest.length})
                </legend>
                <div className="flex gap-3 flex-wrap">
                  {manifest.map((tool) => (
                    <label
                      key={tool}
                      className="text-xs text-text-secondary flex items-center gap-1"
                    >
                      <input
                        type="checkbox"
                        aria-label={`${key} tool ${tool}`}
                        checked={allowed === null || allowed.includes(tool)}
                        onChange={(e) => {
                          // `null` means "every tool", which only the built-ins
                          // start with. The first tick turns that into an
                          // explicit list, so a later server-side change to the
                          // manifest cannot silently widen what the model sees.
                          const base = allowed === null ? manifest : allowed;
                          put(key, {
                            tools: e.target.checked
                              ? [...base, tool]
                              : base.filter((t) => t !== tool),
                          });
                        }}
                      />
                      {tool}
                    </label>
                  ))}
                </div>
              </fieldset>
            )}
          </div>
        );
      })}

      <div className="flex items-center gap-2">
        <input
          className={input}
          placeholder="new server name"
          aria-label="new server name"
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
        />
        <button type="button" className="text-xs text-accent-strong" onClick={add}>
          Add server
        </button>
      </div>
      {keyError && (
        <p className="text-[11px] text-status-red" role="alert">
          {keyError}
        </p>
      )}
    </div>
  );
}
