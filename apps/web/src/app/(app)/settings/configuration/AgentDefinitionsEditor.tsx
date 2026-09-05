"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import type {
  AgentDefinitionEntry,
  AgentProbeDetails,
  CatalogEntry,
  McpServerEntry,
  ProbeResult,
  SettingValue,
  ToolRefEntry,
} from "@/types/settings";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

/** Re-seeded by the settings model, so they lock rather than delete. */
export const BUILTIN_AGENT_KEYS = new Set(["static", "dynamic", "network", "judge"]);
const SLUG = /^[a-z][a-z0-9_-]{0,31}$/;
/** Roles that read a static provider; the others have nothing to point at. */
const PROVIDER_ROLES = new Set(["static", "generic"]);

export const EMPTY_DEFINITION: AgentDefinitionEntry = {
  role: "generic",
  label: "",
  prompt: "",
  tools: [],
  static_provider: null,
  enabled: true,
};

/**
 * The whole `core.agents.definitions` leaf, as a list of cards.
 *
 * One staged value for the whole map, exactly as `ServerMapEditor` stages the
 * whole server map: the PATCH body is the full dict, so sub-project A's apply
 * bar, hidden-dirty count and reset behaviour need no special case, and a
 * half-applied map cannot happen.
 *
 * A built-in card shows a lock and only its enabled switch, because that is
 * the only edit the settings model accepts. Its prompt is shown read-only from
 * the agent probe rather than reconstructed here — the built-in assembly
 * depends on the agent's static provider and only the API can say what it
 * comes to.
 */
export default function AgentDefinitionsEditor({
  entry,
  current,
  staged,
  servers,
  staticProviders,
  onChange,
}: {
  entry: CatalogEntry;
  current: SettingValue | undefined;
  staged: unknown;
  servers: Record<string, McpServerEntry>;
  staticProviders: string[];
  onChange: (value: Record<string, AgentDefinitionEntry>) => void;
}) {
  const value = (staged ?? current?.value ?? entry.default ?? {}) as Record<
    string,
    AgentDefinitionEntry
  >;
  const [newKey, setNewKey] = useState("");
  const [keyError, setKeyError] = useState<string | null>(null);
  const [probes, setProbes] = useState<Record<string, ProbeResult | "running">>({});
  const [manifests, setManifests] = useState<Record<string, string[]>>({});

  const put = (key: string, next: Partial<AgentDefinitionEntry>) =>
    onChange({ ...value, [key]: { ...value[key], ...next } });

  const add = (from?: string) => {
    const key = newKey.trim();
    if (!SLUG.test(key)) {
      setKeyError("lowercase, starts with a letter, at most 32 of a-z 0-9 - _");
      return;
    }
    if (key in value) {
      setKeyError("an agent with that name already exists");
      return;
    }
    setKeyError(null);
    setNewKey("");
    const source = from ? value[from] : undefined;
    const resolvedPrompt =
      from && (probes[from] as ProbeResult | undefined)?.ok
        ? ((probes[from] as ProbeResult).details as AgentProbeDetails | null)
        : null;
    onChange({
      ...value,
      [key]: source
        ? {
            ...source,
            label: source.label ? `${source.label} (copy)` : key,
            // A clone starts from what its source *resolves to*, so an
            // operator can see and edit the built-in prompt rather than
            // guessing it. Left null when the source has not been resolved
            // yet, which still means "the built-in prompt".
            prompt: source.prompt ?? (resolvedPrompt ? null : null),
            tools: source.tools.map((t) => ({ ...t })),
          }
        : { ...EMPTY_DEFINITION },
    });
  };

  const remove = (key: string) => {
    if (BUILTIN_AGENT_KEYS.has(key)) {
      put(key, { enabled: false });
      return;
    }
    const next = { ...value };
    delete next[key];
    onChange(next);
  };

  const resolve = async (key: string) => {
    setProbes((p) => ({ ...p, [key]: "running" }));
    try {
      const result = await api.probeAgent(key, { "core.agents.definitions": value });
      setProbes((p) => ({ ...p, [key]: result }));
    } catch (e) {
      setProbes((p) => ({
        ...p,
        [key]: {
          ok: false,
          latency_ms: 0,
          detail: getErrorMessage(e),
          models: null,
          tools: null,
          details: null,
        },
      }));
    }
  };

  const loadManifest = async (server: string) => {
    try {
      const result = await api.testMcpServer(server, { "core.mcp.servers": servers });
      setManifests((m) => ({ ...m, [server]: result.tools ?? [] }));
    } catch {
      setManifests((m) => ({ ...m, [server]: [] }));
    }
  };

  const toggleRef = (key: string, ref: ToolRefEntry, on: boolean) => {
    const same = (a: ToolRefEntry) =>
      a.kind === ref.kind && a.server === ref.server && a.name === ref.name;
    const tools = value[key].tools;
    put(key, { tools: on ? [...tools, ref] : tools.filter((t) => !same(t)) });
  };

  const hasRef = (key: string, ref: ToolRefEntry) =>
    value[key].tools.some(
      (t) => t.kind === ref.kind && t.server === ref.server && t.name === ref.name
    );

  return (
    <div className="space-y-3" data-testid="agent-definitions-editor">
      {Object.entries(value).map(([key, agent]) => {
        const locked = BUILTIN_AGENT_KEYS.has(key);
        const result = probes[key];
        const details =
          result && result !== "running"
            ? ((result.details as AgentProbeDetails | null) ?? null)
            : null;
        return (
          <div key={key} className="border border-border rounded p-3" data-agent={key}>
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="text-sm text-text-primary font-mono">
                {key}
                <span className="ml-2 text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-border text-text-muted">
                  {agent.role}
                </span>
                {locked && (
                  <span className="ml-2 text-[10px] uppercase tracking-wider text-text-muted">
                    built in
                  </span>
                )}
              </span>
              <div className="flex items-center gap-3">
                <label className="text-xs text-text-secondary flex items-center gap-1">
                  <input
                    type="checkbox"
                    aria-label={`${key} enabled`}
                    checked={agent.enabled}
                    onChange={(e) => put(key, { enabled: e.target.checked })}
                  />
                  enabled
                </label>
                <button
                  type="button"
                  className="text-xs text-accent-strong disabled:opacity-50"
                  disabled={result === "running"}
                  onClick={() => void resolve(key)}
                >
                  Resolve
                </button>
                <button
                  type="button"
                  className="text-xs text-accent-strong"
                  onClick={() => add(key)}
                >
                  Clone
                </button>
                {!locked && (
                  <button
                    type="button"
                    className="text-xs text-text-secondary"
                    onClick={() => remove(key)}
                  >
                    Remove
                  </button>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <label className="block">
                <span className="text-text-muted">Label</span>
                <input
                  className={input}
                  aria-label={`${key} label`}
                  disabled={locked}
                  value={agent.label}
                  onChange={(e) => put(key, { label: e.target.value })}
                />
              </label>
              {PROVIDER_ROLES.has(agent.role) && (
                <label className="block">
                  <span className="text-text-muted">Static provider</span>
                  <select
                    className={input}
                    aria-label={`${key} static provider`}
                    disabled={locked}
                    value={agent.static_provider ?? ""}
                    onChange={(e) =>
                      put(key, { static_provider: e.target.value || null })
                    }
                  >
                    <option value="">Inherit from settings</option>
                    {staticProviders.map((p) => (
                      <option key={p} value={p}>
                        {p}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              <label className="block sm:col-span-2">
                <span className="text-text-muted">
                  {locked ? "Prompt (built in, read-only)" : "Prompt"}
                </span>
                <textarea
                  className={input}
                  rows={4}
                  aria-label={`${key} prompt`}
                  disabled={locked}
                  placeholder={
                    agent.prompt === null ? "the built-in prompt for this role" : ""
                  }
                  value={
                    locked
                      ? details
                        ? `built-in prompt, ${details.prompt_chars} characters (sha256 ${details.prompt_sha256.slice(0, 12)}…)`
                        : "press Resolve to see the built-in prompt this agent receives"
                      : (agent.prompt ?? "")
                  }
                  onChange={(e) => put(key, { prompt: e.target.value })}
                />
              </label>
              <label className="block">
                <span className="text-text-muted">LLM provider</span>
                <input
                  className={input}
                  aria-label={`${key} llm provider`}
                  placeholder="inherit"
                  defaultValue={details?.llm.provider ?? ""}
                  readOnly
                />
              </label>
              <label className="block">
                <span className="text-text-muted">LLM model</span>
                <input
                  className={input}
                  aria-label={`${key} llm model`}
                  placeholder={`set llm.agents.${key}.model to override`}
                  defaultValue={details?.llm.model ?? ""}
                  readOnly
                />
              </label>
            </div>

            <fieldset className="mt-2">
              <legend className="text-xs text-text-muted">Tools</legend>
              {agent.role === "generic" && (
                <label className="text-xs text-text-secondary flex items-center gap-1">
                  <input
                    type="checkbox"
                    aria-label={`${key} provider tools`}
                    checked={hasRef(key, { kind: "provider", server: null, name: null })}
                    onChange={(e) =>
                      toggleRef(key, { kind: "provider", server: null, name: null }, e.target.checked)
                    }
                  />
                  its static provider&rsquo;s tools
                </label>
              )}
              {Object.keys(servers).map((server) => (
                <div key={server} className="mt-1">
                  <div className="flex items-center gap-2">
                    <label className="text-xs text-text-secondary flex items-center gap-1">
                      <input
                        type="checkbox"
                        aria-label={`${key} server ${server}`}
                        disabled={locked}
                        checked={hasRef(key, { kind: "mcp", server, name: null })}
                        onChange={(e) =>
                          toggleRef(key, { kind: "mcp", server, name: null }, e.target.checked)
                        }
                      />
                      {server} (all allowed tools)
                    </label>
                    <button
                      type="button"
                      className="text-[11px] text-accent-strong"
                      onClick={() => void loadManifest(server)}
                    >
                      List tools
                    </button>
                  </div>
                  <div className="flex gap-3 flex-wrap ml-4">
                    {(manifests[server] ?? []).map((tool) => (
                      <label
                        key={tool}
                        className="text-xs text-text-secondary flex items-center gap-1"
                      >
                        <input
                          type="checkbox"
                          aria-label={`${key} tool ${server}.${tool}`}
                          disabled={locked}
                          checked={hasRef(key, { kind: "mcp", server, name: tool })}
                          onChange={(e) =>
                            toggleRef(key, { kind: "mcp", server, name: tool }, e.target.checked)
                          }
                        />
                        {tool}
                      </label>
                    ))}
                  </div>
                </div>
              ))}
            </fieldset>

            {result === "running" && (
              <p className="text-[11px] text-text-muted mt-2">resolving…</p>
            )}
            {result && result !== "running" && (
              <p
                className={`text-[11px] mt-2 ${result.ok ? "text-status-green" : "text-status-red"}`}
                role="status"
              >
                {result.ok ? "ok" : "failed"} · {result.latency_ms} ms · {result.detail}
                {details ? ` · prompt ${details.prompt_chars} chars` : ""}
              </p>
            )}
          </div>
        );
      })}

      <div className="flex items-center gap-2">
        <input
          className={input}
          placeholder="new agent name"
          aria-label="new agent name"
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
        />
        <button type="button" className="text-xs text-accent-strong" onClick={() => add()}>
          Add agent
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
