"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import type { CatalogEntry, McpServerEntry, ProbeResult, SettingValue } from "@/types/settings";
import { deepEqual, mapKeyError, putEntry, removeEntry } from "./mapEditorHelpers";
import SecretField, { type SecretStatus } from "./SecretField";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

/** Built-ins are re-seeded by the settings model, so they disable rather than delete. */
const BUILTIN = new Set(["network", "threatintel"]);
const ROLES = ["static", "dynamic", "network", "judge"] as const;
/** Mirrors `RESERVED_SERVER_KEYS` in `src/maljan/core/config.py`. Two of these
 *  (`network`, `threatintel`) are also pre-populated built-ins and never reach
 *  `add()`; `ghidra` and `cape` are reserved but not pre-populated, so without
 *  this check they would pass client validation and fail only on apply. */
export const RESERVED_SERVER_KEYS = new Set(["network", "threatintel", "ghidra", "cape"]);
/** What a set token looks like from outside; identical to the API's mask. */
const TOKEN_MASK = "**********";

const TOKEN_SOURCE_LABEL: Record<string, string> = {
  ui: "set from the UI",
  env: "set in .env",
  default: "not set",
};

const TRANSPORTS = ["stdio", "http", "streamable-http", "sse"];
const TOOL_SELECTIONS = ["curated", "dynamic", "all"];

/* B6 (dev audit 2026-09-06): a probe result describes the server as it was
 * configured when the button was pressed. Editing what the probe dialled —
 * the transport and its connection fields — leaves the green "3 tools: …"
 * line describing a server that no longer exists, so the result is dropped
 * with the edit. The allow-list, the agent bindings, the label and the
 * enabled switch do not change what a probe would reach, and the tool tick
 * boxes are rendered from the probe's own manifest, so they must not clear
 * it. */
const PROBE_INPUTS = new Set<keyof McpServerEntry>([
  "transport", "command", "args", "cwd", "env", "env_allow", "url", "auth_token",
]);

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

/** One of the small state dots in the server list. */
function Dot({ label, className }: { label: string; className: string }) {
  return (
    <span
      role="img"
      aria-label={label}
      title={label}
      className={`inline-block w-1.5 h-1.5 rounded-full shrink-0 ${className}`}
    />
  );
}

/**
 * The fixed environment a stdio server is started with, as JSON.
 *
 * `env_allow` names variables inherited from the worker's own environment;
 * `env` sets them outright, and a server that needs one (Qu1cksc0pe wants
 * `SC0PE_MCP_TRANSPORT=stdio`) could not be configured from this screen at
 * all — the operator had to wrap the command in a shell script. The text is
 * local state so a half-typed object is not reformatted under the cursor;
 * only a parsed object of string values is staged, and an empty box is `{}`.
 */
function EnvMapField({
  serverKey,
  env,
  onChange,
}: {
  serverKey: string;
  env: Record<string, string>;
  onChange: (env: Record<string, string>) => void;
}) {
  const [text, setText] = useState(() =>
    Object.keys(env).length ? JSON.stringify(env, null, 2) : "",
  );
  const [bad, setBad] = useState<string | null>(null);

  const stage = (next: string) => {
    setText(next);
    if (next.trim() === "") {
      setBad(null);
      onChange({});
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(next);
    } catch (err) {
      setBad((err as Error).message);
      return;
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      setBad("expected an object of name to value");
      return;
    }
    const entries = Object.entries(parsed as Record<string, unknown>);
    if (entries.some(([, v]) => typeof v !== "string")) {
      setBad("every value must be a string");
      return;
    }
    setBad(null);
    onChange(Object.fromEntries(entries) as Record<string, string>);
  };

  return (
    <label className="block">
      <span className="text-text-muted">Environment variables (JSON object)</span>
      <textarea
        className={`${input} font-mono`}
        rows={3}
        aria-label={`${serverKey} env`}
        aria-invalid={bad ? true : undefined}
        value={text}
        onChange={(e) => stage(e.target.value)}
      />
      {bad && (
        <div className="text-[11px] text-status-red mt-1" role="alert">
          Invalid environment map: {bad}
        </div>
      )}
    </label>
  );
}

/**
 * The whole `core.mcp.servers` leaf, as a master–detail editor.
 *
 * A card per server stacked down the page made the leaf as tall as the number
 * of servers, and every server's connection fields, tool list and agent
 * bindings were open at once. The list on the left carries only what tells
 * one server from another — key, transport, enabled, whether it differs from
 * what is saved, and the last probe verdict — and the selected server's form
 * fills the right-hand side in three named sections.
 *
 * One staged value for the whole map, not one per card: the PATCH body is the
 * full dict, so the apply bar, the hidden-dirty count and the reset behaviour
 * from sub-project A all apply unchanged, and a half-applied map — three
 * servers saved and the fourth rejected — cannot happen.
 *
 * The token field rides inside that same dict and behaves the way every other
 * secret does: what arrives is the mask (or an empty string), the input is a
 * password field that only appears once the operator asks to edit, an
 * untouched card sends the mask straight back and the API reads that as
 * "leave the stored row alone", and "Clear" stages `null`. The value the
 * operator types exists only in this component's state until it is applied;
 * it never comes back from a GET.
 */
export default function ServerMapEditor({
  entry,
  current,
  staged,
  errors = {},
  onChange,
}: {
  entry: CatalogEntry;
  current: SettingValue | undefined;
  staged: unknown;
  /** The full validation-error map, keyed by dotted path, so an error like
   *  `core.mcp.servers.<key>.command` lands on the server that caused it. */
  errors?: Record<string, string>;
  onChange: (value: Record<string, McpServerEntry>) => void;
}) {
  const value = (staged ?? current?.value ?? entry.default ?? {}) as Record<string, McpServerEntry>;
  /** What is stored right now, for the "changed" dot: a server differs when
   *  the staged map has edited it, added it, or the leaf has no saved value
   *  at all and every entry in it is new. */
  const savedMap = (current?.value ?? entry.default ?? {}) as Record<string, McpServerEntry>;
  const [newKey, setNewKey] = useState("");
  const [keyError, setKeyError] = useState<string | null>(null);
  const [probes, setProbes] = useState<Record<string, ProbeResult | "running">>({});
  /** Servers whose probe result was dropped by an edit to what it dialled, so
   *  the Tools section can say why the tool list went away. */
  const [staleProbe, setStaleProbe] = useState<Record<string, boolean>>({});
  /** The server the detail pane shows. Null until something is picked, and a
   *  key that has since been removed falls back to the first one. */
  const [picked, setPicked] = useState<string | null>(null);

  const keys = Object.keys(value);
  const selected = picked !== null && picked in value ? picked : (keys[0] ?? null);

  const put = (key: string, next: Partial<McpServerEntry>) => {
    if (Object.keys(next).some((k) => PROBE_INPUTS.has(k as keyof McpServerEntry))) {
      if (probes[key] !== undefined) {
        setProbes((p) => {
          const n = { ...p };
          delete n[key];
          return n;
        });
        setStaleProbe((s) => ({ ...s, [key]: true }));
      }
    }
    onChange(putEntry(value, key, next));
  };

  const add = () => {
    const key = newKey.trim();
    const problem = mapKeyError(key, value, "server", RESERVED_SERVER_KEYS);
    if (problem) {
      setKeyError(problem);
      return;
    }
    setKeyError(null);
    setNewKey("");
    setPicked(key);
    onChange({ ...value, [key]: { ...EMPTY_SERVER } });
  };

  const remove = (key: string) => {
    if (BUILTIN.has(key)) {
      put(key, { enabled: false });
      return;
    }
    onChange(removeEntry(value, key));
  };

  const probe = async (key: string) => {
    setStaleProbe((s) => ({ ...s, [key]: false }));
    setProbes((p) => ({ ...p, [key]: "running" }));
    try {
      const result = await api.testMcpServer(key, { "core.mcp.servers": value });
      setProbes((p) => ({ ...p, [key]: result }));
    } catch (e) {
      setProbes((p) => ({
        ...p,
        [key]: { ok: false, latency_ms: 0, detail: getErrorMessage(e), models: null, tools: null, details: null },
      }));
    }
  };

  const errorFor = (key: string): string | undefined =>
    Object.entries(errors).find(
      ([k]) => k === `${entry.key}.${key}` || k.startsWith(`${entry.key}.${key}.`)
    )?.[1];

  const server = selected === null ? null : value[selected];
  const result = selected === null ? undefined : probes[selected];
  const manifest = result && result !== "running" ? result.tools : null;
  const allowed = server ? server.tools : null;
  const detailError = selected === null ? undefined : errorFor(selected);
  const tokenSource = server?.auth_token_source ?? "default";
  /** What the shared secret control shows for this token: a value the operator
   *  typed is staged, `null` is a clear, the mask (or an empty string) is
   *  whatever the API reported. */
  const tokenStatus: SecretStatus =
    server === null
      ? "not-set"
      : server.auth_token === null
        ? "cleared"
        : server.auth_token !== "" && server.auth_token !== TOKEN_MASK
          ? "staged"
          : tokenSource === "default"
            ? "not-set"
            : "set";

  return (
    <div
      className="grid md:grid-cols-[260px_minmax(0,1fr)] gap-4"
      data-testid="server-map-editor"
    >
      <div className="min-w-0">
        <ul
          role="listbox"
          aria-label="Tool servers"
          className="border border-border rounded divide-y divide-border"
        >
          {keys.map((key) => {
            const item = value[key];
            const itemResult = probes[key];
            const verdict =
              itemResult && itemResult !== "running" ? (itemResult.ok ? "ok" : "failed") : null;
            const changed = !deepEqual(item, savedMap[key]);
            return (
              <li
                key={key}
                role="option"
                data-server={key}
                aria-selected={key === selected}
                tabIndex={key === selected ? 0 : -1}
                onClick={() => setPicked(key)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setPicked(key);
                  }
                }}
                className={`px-2 py-1.5 cursor-pointer focus:outline-none focus:ring-1 focus:ring-accent ${
                  key === selected ? "bg-accent/10" : "hover:bg-bg-deep"
                }`}
              >
                <div className="flex items-center gap-2 min-w-0">
                  <Dot
                    label={item.enabled ? "enabled" : "disabled"}
                    className={item.enabled ? "bg-status-green" : "bg-border"}
                  />
                  <span className="text-sm font-mono text-text-primary truncate">{key}</span>
                  {changed && <Dot label="changed" className="bg-accent-strong" />}
                  {errorFor(key) && <Dot label="invalid" className="bg-status-red" />}
                </div>
                <div className="flex items-center gap-2 text-[11px] text-text-muted pl-3.5">
                  <span>{item.transport}</span>
                  {verdict && (
                    <span
                      className={
                        verdict === "ok" ? "text-status-green" : "text-status-red"
                      }
                    >
                      {verdict}
                    </span>
                  )}
                </div>
              </li>
            );
          })}
          {keys.length === 0 && (
            <li className="px-2 py-1.5 text-xs text-text-muted">no servers configured</li>
          )}
        </ul>

        <div className="flex items-center gap-2 mt-2">
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
          <p className="text-[11px] text-status-red mt-1" role="alert">
            {keyError}
          </p>
        )}
      </div>

      {selected !== null && server && (
        <section
          key={selected}
          data-server-detail={selected}
          aria-label={`Server ${selected}`}
          className="min-w-0 border border-border rounded p-3 space-y-3"
        >
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <span className="text-sm text-text-primary font-mono">{selected}</span>
            <div className="flex items-center gap-3">
              <label className="text-xs text-text-secondary flex items-center gap-1">
                <input
                  type="checkbox"
                  aria-label={`${selected} enabled`}
                  checked={server.enabled}
                  onChange={(e) => put(selected, { enabled: e.target.checked })}
                />
                enabled
              </label>
              <button
                type="button"
                className="text-xs text-accent-strong disabled:opacity-50"
                disabled={result === "running"}
                onClick={() => void probe(selected)}
              >
                Test
              </button>
              <button
                type="button"
                className="text-xs text-text-secondary"
                onClick={() => remove(selected)}
              >
                {BUILTIN.has(selected) ? "Disable" : "Remove"}
              </button>
            </div>
          </div>

          <label className="block text-xs">
            <span className="text-text-muted">Label</span>
            <input
              className={input}
              aria-label={`${selected} label`}
              value={server.label}
              onChange={(e) => put(selected, { label: e.target.value })}
            />
          </label>

          {result === "running" && <p className="text-[11px] text-text-muted">testing…</p>}
          {result && result !== "running" && (
            <p
              className={`text-[11px] ${result.ok ? "text-status-green" : "text-status-red"}`}
              role="status"
            >
              {result.ok ? "ok" : "failed"} · {result.latency_ms} ms · {result.detail}
            </p>
          )}
          {detailError && (
            <p className="text-[11px] text-status-red" role="alert">
              {detailError}
            </p>
          )}

          <fieldset className="border border-border rounded p-2">
            <legend className="text-xs text-text-muted px-1">Connection</legend>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <label className="block">
                <span className="text-text-muted">Transport</span>
                <select
                  className={input}
                  aria-label={`${selected} transport`}
                  value={server.transport}
                  onChange={(e) => put(selected, { transport: e.target.value })}
                >
                  {TRANSPORTS.map((t) => (
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
                      aria-label={`${selected} command`}
                      value={server.command}
                      onChange={(e) => put(selected, { command: e.target.value })}
                    />
                  </label>
                  <label className="block">
                    <span className="text-text-muted">Arguments (one per line)</span>
                    <textarea
                      className={input}
                      rows={2}
                      aria-label={`${selected} args`}
                      value={server.args.join("\n")}
                      onChange={(e) =>
                        put(selected, { args: e.target.value.split("\n").filter((a) => a !== "") })
                      }
                    />
                  </label>
                  <label className="block">
                    <span className="text-text-muted">Working directory</span>
                    <input
                      className={input}
                      aria-label={`${selected} cwd`}
                      value={server.cwd}
                      onChange={(e) => put(selected, { cwd: e.target.value })}
                    />
                  </label>
                  <EnvMapField
                    serverKey={selected}
                    env={server.env ?? {}}
                    onChange={(env) => put(selected, { env })}
                  />
                  <label className="block">
                    <span className="text-text-muted">
                      Environment names passed through (one per line)
                    </span>
                    <textarea
                      className={input}
                      rows={2}
                      aria-label={`${selected} env allow`}
                      value={server.env_allow.join("\n")}
                      onChange={(e) =>
                        put(selected, {
                          env_allow: e.target.value.split("\n").filter((a) => a !== ""),
                        })
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
                      aria-label={`${selected} url`}
                      value={server.url}
                      onChange={(e) => put(selected, { url: e.target.value })}
                    />
                  </label>
                  <div className="block">
                    <span className="text-text-muted">Auth token</span>
                    <div className="py-1.5">
                      <SecretField
                        id={`server-token-${selected}`}
                        name={`server-token-${selected}`}
                        title={`${selected} auth token`}
                        status={tokenStatus}
                        editable={entry.editable}
                        labels={{ replace: "Replace token" }}
                        /* The three words this screen has always used for a
                           server token — where it comes from, not the generic
                           `set · …hint · source` line — and the attribute the
                           spec reads them through. */
                        statusText={
                          tokenStatus === "set" || tokenStatus === "not-set"
                            ? (TOKEN_SOURCE_LABEL[tokenSource] ?? "not set")
                            : undefined
                        }
                        statusAttrs={{ "data-token-state": selected }}
                        onStage={(v) => put(selected, { auth_token: v })}
                        onCancel={() =>
                          // Closing the field abandons whatever was typed and
                          // puts the mask back, which the API reads as "leave
                          // the stored token alone".
                          put(selected, {
                            auth_token: tokenSource === "default" ? "" : TOKEN_MASK,
                          })
                        }
                        onClear={() =>
                          // `null` is how every secret in this project is
                          // cleared: the API deletes the row rather than
                          // storing an empty one.
                          put(selected, { auth_token: null as unknown as string })
                        }
                      />
                    </div>
                  </div>
                </>
              )}
            </div>
          </fieldset>

          {/* WEB-2 (dev audit 2026-09-06): both of these are on every server
              the editor creates, both are read by the providers that drive a
              server (`providers/static/generic_mcp.py`, `ghidra.py`), and
              neither had a control anywhere on this screen — a new server
              kept whatever the default happened to be with no way to change
              it. */}
          <fieldset className="border border-border rounded p-2">
            <legend className="text-xs text-text-muted px-1">Tools</legend>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <label className="block">
                <span className="text-text-muted">Tool selection</span>
                <select
                  className={input}
                  aria-label={`${selected} tool selection`}
                  disabled={server.use_all_tools}
                  value={server.tool_selection}
                  onChange={(e) => put(selected, { tool_selection: e.target.value })}
                >
                  {TOOL_SELECTIONS.map((t) => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </label>
              <label className="text-xs text-text-secondary flex items-center gap-1 self-end pb-1.5">
                <input
                  type="checkbox"
                  aria-label={`${selected} force all tools`}
                  checked={server.use_all_tools}
                  onChange={(e) => put(selected, { use_all_tools: e.target.checked })}
                />
                force every tool, whatever the selection says
              </label>
            </div>

            {manifest && manifest.length > 0 ? (
              <div className="mt-2">
                <p className="text-xs text-text-muted">
                  Tools the model may call ({allowed === null ? "all" : allowed.length} of{" "}
                  {manifest.length})
                </p>
                <div className="flex gap-3 flex-wrap mt-1">
                  {manifest.map((tool) => (
                    <label
                      key={tool}
                      className="text-xs text-text-secondary flex items-center gap-1"
                    >
                      <input
                        type="checkbox"
                        aria-label={`${selected} tool ${tool}`}
                        checked={allowed === null || allowed.includes(tool)}
                        onChange={(e) => {
                          // `null` means "every tool", which only the built-ins
                          // start with. The first tick turns that into an
                          // explicit list, so a later server-side change to the
                          // manifest cannot silently widen what the model sees.
                          const base = allowed === null ? manifest : allowed;
                          put(selected, {
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
              </div>
            ) : (
              <div className="mt-2 flex items-center gap-2">
                <p className="text-xs text-text-muted">
                  {staleProbe[selected]
                    ? "Connection changed; run Test again"
                    : "Run Test to load the tool list"}
                </p>
                {/* Named apart from the header's Test so a "Test" button is
                    never ambiguous on this pane. */}
                <button
                  type="button"
                  className="text-xs text-accent-strong disabled:opacity-50"
                  disabled={result === "running"}
                  onClick={() => void probe(selected)}
                >
                  Load tool list
                </button>
              </div>
            )}
          </fieldset>

          <fieldset className="border border-border rounded p-2">
            <legend className="text-xs text-text-muted px-1">Agents</legend>
            <div className="flex gap-3 flex-wrap">
              {ROLES.map((role) => (
                <label key={role} className="text-xs text-text-secondary flex items-center gap-1">
                  <input
                    type="checkbox"
                    aria-label={`${selected} agent ${role}`}
                    checked={server.agents.includes(role)}
                    onChange={(e) =>
                      put(selected, {
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
        </section>
      )}
    </div>
  );
}
