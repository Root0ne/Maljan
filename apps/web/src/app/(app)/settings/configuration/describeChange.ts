/**
 * Turns one staged catalog change into a human-readable review line for the
 * changes bar and the guide's review step. Pure and side-effect free: no
 * network, no React. `describeChange` never renders a secret value — the
 * masking rules below are the single place that decides what a viewer sees
 * for a token or a `secret`-typed leaf.
 */
import type {
  AgentDefinitionEntry,
  CatalogEntry,
  ProfileEntry,
} from "@/types/settings";
import type { AgentLLMOverride } from "./AgentDefinitionsEditor";

export interface ChangeLine {
  key: string;
  title: string;
  summary: string;
  detail?: string[];
  applies: CatalogEntry["applies"];
}

const MAX_SCALAR_LENGTH = 60;

/** Renders a scalar for a `before → after` line: `unset` for null/undefined,
 *  plain (unquoted) text for strings, `String()` for everything else. Long
 *  strings are cut to 60 chars with an ellipsis. Exported so tests (and any
 *  other scalar-rendering call site) share one rule. */
export function formatScalar(v: unknown): string {
  if (v === null || v === undefined) return "unset";
  if (typeof v === "string") return truncate(v);
  return String(v);
}

function truncate(s: string): string {
  return s.length > MAX_SCALAR_LENGTH ? `${s.slice(0, MAX_SCALAR_LENGTH)}…` : s;
}

function formatBool(v: unknown): string {
  if (v === null || v === undefined) return "unset";
  return v ? "on" : "off";
}

/** Structural equality for two catalog values — used everywhere a "did this
 *  leaf actually change" question needs an answer that doesn't care about
 *  key order (`JSON.stringify` is order-sensitive for object keys, but every
 *  caller here compares against a freshly-decoded document or freshly-read
 *  state, not two independently-serialised copies of the same map, so that
 *  edge case does not arise in practice). Exported so `importPreview.ts`
 *  shares this one rule instead of carrying its own copy. */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || a === undefined || b === null || b === undefined) return a === b;
  if (typeof a !== "object" || typeof b !== "object") return false;
  return JSON.stringify(a) === JSON.stringify(b);
}

/** Object.keys(before), then any extra keys `after` introduces, so map diffs
 *  read in a stable, mostly-original order. */
function collectKeys(
  before: Record<string, unknown>,
  after: Record<string, unknown>
): string[] {
  const keys = Object.keys(before);
  const seen = new Set(keys);
  for (const k of Object.keys(after)) {
    if (!seen.has(k)) {
      keys.push(k);
      seen.add(k);
    }
  }
  return keys;
}

function asRecord(v: unknown): Record<string, unknown> {
  return (v ?? {}) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Generic list / dict / json leaves (no special key handling below applies)
// ---------------------------------------------------------------------------

function describeListChange(before: unknown[], after: unknown[]): {
  summary: string;
  detail?: string[];
} {
  const added = after.filter((v) => !before.some((b) => deepEqual(b, v)));
  const removed = before.filter((v) => !after.some((a) => deepEqual(a, v)));
  const detail = [
    ...added.map((v) => `+ ${formatScalar(v)}`),
    ...removed.map((v) => `− ${formatScalar(v)}`),
  ];
  return {
    summary: `+${added.length} −${removed.length} entries`,
    detail: detail.length ? detail : undefined,
  };
}

function describeDictChange(
  before: Record<string, unknown>,
  after: Record<string, unknown>
): { summary: string; detail?: string[] } {
  const keys = collectKeys(before, after);
  const detail: string[] = [];
  let added = 0;
  let removed = 0;
  for (const key of keys) {
    const inBefore = Object.prototype.hasOwnProperty.call(before, key);
    const inAfter = Object.prototype.hasOwnProperty.call(after, key);
    if (!inBefore && inAfter) {
      added++;
      detail.push(`+ ${key}: ${formatScalar(after[key])}`);
    } else if (inBefore && !inAfter) {
      removed++;
      detail.push(`− ${key}: ${formatScalar(before[key])}`);
    } else if (!deepEqual(before[key], after[key])) {
      detail.push(`~ ${key}: ${formatScalar(before[key])} → ${formatScalar(after[key])}`);
    }
  }
  return {
    summary: `+${added} −${removed} entries`,
    detail: detail.length ? detail : undefined,
  };
}

function describeCollection(before: unknown, after: unknown): {
  summary: string;
  detail?: string[];
} {
  if (Array.isArray(before) || Array.isArray(after)) {
    return describeListChange(
      Array.isArray(before) ? before : [],
      Array.isArray(after) ? after : []
    );
  }
  return describeDictChange(asRecord(before), asRecord(after));
}

// ---------------------------------------------------------------------------
// core.mcp.servers
// ---------------------------------------------------------------------------

const SERVER_FIELDS = [
  "transport",
  "url",
  "command",
  "args",
  "cwd",
  "env",
  "env_allow",
  "label",
  "tool_selection",
  "use_all_tools",
  "agents",
] as const;

function hasToken(v: unknown): boolean {
  return v !== null && v !== undefined && v !== "";
}

function describeTokenChange(before: unknown, after: unknown): string | null {
  const wasSet = hasToken(before);
  const isSet = hasToken(after);
  if (!wasSet && !isSet) return null;
  if (wasSet && !isSet) return "token cleared";
  if (!wasSet && isSet) return "token set";
  if (before === after) return null;
  return "token replaced";
}

function describeServerMap(before: unknown, after: unknown): {
  summary: string;
  detail?: string[];
} {
  const b = asRecord(before);
  const a = asRecord(after);
  const keys = collectKeys(b, a);
  const detail: string[] = [];
  let changedCount = 0;

  for (const key of keys) {
    const inBefore = Object.prototype.hasOwnProperty.call(b, key);
    const inAfter = Object.prototype.hasOwnProperty.call(a, key);
    if (!inBefore && inAfter) {
      detail.push(`${key}: added`);
      changedCount++;
      continue;
    }
    if (inBefore && !inAfter) {
      detail.push(`${key}: removed`);
      changedCount++;
      continue;
    }

    const bs = asRecord(b[key]);
    const as = asRecord(a[key]);
    const enabledChanged = bs.enabled !== as.enabled;
    const fields: string[] = [];
    for (const field of SERVER_FIELDS) {
      if (!deepEqual(bs[field], as[field])) fields.push(field);
    }
    if (!deepEqual(bs.tools, as.tools)) {
      const beforeCount =
        bs.tools === null || bs.tools === undefined ? "all" : (bs.tools as unknown[]).length;
      const afterCount =
        as.tools === null || as.tools === undefined ? "all" : (as.tools as unknown[]).length;
      fields.push(`tools (${beforeCount} → ${afterCount})`);
    }
    const tokenChange = describeTokenChange(bs.auth_token, as.auth_token);
    if (tokenChange) fields.push(tokenChange);

    // A flip that happens alongside other edits joins the `changed:` list
    // rather than being dropped for them: "disabled" is usually the most
    // consequential half of such a change.
    if (enabledChanged) fields.unshift(as.enabled ? "enabled" : "disabled");

    if (fields.length === 1 && enabledChanged) {
      detail.push(`${key}: ${as.enabled ? "enabled" : "disabled"}`);
      changedCount++;
    } else if (fields.length > 0) {
      detail.push(`${key}: changed: ${fields.join(", ")}`);
      changedCount++;
    }
  }

  return {
    summary: `${changedCount} server(s) changed`,
    detail: detail.length ? detail : undefined,
  };
}

// ---------------------------------------------------------------------------
// core.agents.definitions
// ---------------------------------------------------------------------------

const DEFINITION_FIELDS: [keyof AgentDefinitionEntry, string][] = [
  ["prompt", "prompt"],
  ["tools", "tools"],
  ["static_provider", "static provider"],
  ["label", "label"],
  ["role", "role"],
];

function findCloneSource(
  def: AgentDefinitionEntry,
  before: Record<string, AgentDefinitionEntry>
): string | null {
  if (!def.label || !def.label.endsWith(" (copy)")) return null;
  for (const [key, source] of Object.entries(before)) {
    if (source.role === def.role) return key;
  }
  return null;
}

function describeDefinitionsMap(before: unknown, after: unknown): {
  summary: string;
  detail?: string[];
} {
  const b = asRecord(before) as Record<string, AgentDefinitionEntry>;
  const a = asRecord(after) as Record<string, AgentDefinitionEntry>;
  const keys = collectKeys(b, a);
  const detail: string[] = [];
  let changedCount = 0;

  for (const key of keys) {
    const inBefore = Object.prototype.hasOwnProperty.call(b, key);
    const inAfter = Object.prototype.hasOwnProperty.call(a, key);
    if (!inBefore && inAfter) {
      const clone = findCloneSource(a[key], b);
      detail.push(clone ? `${key}: added (clone of ${clone})` : `${key}: added`);
      changedCount++;
      continue;
    }
    if (inBefore && !inAfter) {
      detail.push(`${key}: removed`);
      changedCount++;
      continue;
    }

    const bs = b[key];
    const as = a[key];
    const enabledChanged = bs.enabled !== as.enabled;
    const fields: string[] = [];
    for (const [field, label] of DEFINITION_FIELDS) {
      if (!deepEqual(bs[field], as[field])) fields.push(label);
    }

    // Same rule as the server map: an enable/disable that travels with other
    // edits is named in the `changed:` list instead of vanishing.
    if (enabledChanged) fields.unshift(as.enabled ? "enabled" : "disabled");

    if (fields.length === 1 && enabledChanged) {
      detail.push(`${key}: ${as.enabled ? "enabled" : "disabled"}`);
      changedCount++;
    } else if (fields.length > 0) {
      detail.push(`${key}: changed: ${fields.join(", ")}`);
      changedCount++;
    }
  }

  return {
    summary: `${changedCount} agent(s) changed`,
    detail: detail.length ? detail : undefined,
  };
}

// ---------------------------------------------------------------------------
// core.agents.profiles / core.agents.profile
// ---------------------------------------------------------------------------

function describeProfilesMap(before: unknown, after: unknown): {
  summary: string;
  detail?: string[];
} {
  const b = asRecord(before) as Record<string, ProfileEntry>;
  const a = asRecord(after) as Record<string, ProfileEntry>;
  const keys = collectKeys(b, a);
  const detail: string[] = [];
  let changedCount = 0;

  for (const key of keys) {
    const inBefore = Object.prototype.hasOwnProperty.call(b, key);
    const inAfter = Object.prototype.hasOwnProperty.call(a, key);
    if (!inBefore && inAfter) {
      detail.push(`${key}: added`);
      changedCount++;
      continue;
    }
    if (inBefore && !inAfter) {
      detail.push(`${key}: removed`);
      changedCount++;
      continue;
    }

    const bp = b[key];
    const ap = a[key];
    const beforeSet = new Set(bp.analysts);
    const afterSet = new Set(ap.analysts);
    const added = ap.analysts.filter((x) => !beforeSet.has(x));
    const removed = bp.analysts.filter((x) => !afterSet.has(x));
    const sameSet = added.length === 0 && removed.length === 0;
    const analystsDiffer = !deepEqual(bp.analysts, ap.analysts);
    const labelChanged = bp.label !== ap.label;

    // A rename and an analyst edit are two separate facts about one profile:
    // both get a line, and the profile still counts once.
    const lines: string[] = [];
    if (!sameSet) {
      lines.push(`${key}: analysts changed (+${added.length} −${removed.length})`);
    } else if (analystsDiffer) {
      lines.push(`${key}: analysts reordered (${ap.analysts.join(", ")})`);
    }
    if (labelChanged) lines.push(`${key}: label changed`);
    if (lines.length > 0) {
      detail.push(...lines);
      changedCount++;
    }
  }

  return {
    summary: `${changedCount} profile(s) changed`,
    detail: detail.length ? detail : undefined,
  };
}

// ---------------------------------------------------------------------------
// core.llm.agents
// ---------------------------------------------------------------------------

function formatOverride(o: AgentLLMOverride): string {
  const base = `${o.provider}/${o.model}`;
  return o.temperature === null || o.temperature === undefined
    ? base
    : `${base} (temp ${o.temperature})`;
}

function describeLlmAgentsMap(before: unknown, after: unknown): {
  summary: string;
  detail?: string[];
} {
  const b = asRecord(before) as Record<string, AgentLLMOverride>;
  const a = asRecord(after) as Record<string, AgentLLMOverride>;
  const keys = collectKeys(b, a);
  const detail: string[] = [];
  let changedCount = 0;

  for (const key of keys) {
    const inBefore = Object.prototype.hasOwnProperty.call(b, key);
    const inAfter = Object.prototype.hasOwnProperty.call(a, key);
    if (inBefore && !inAfter) {
      detail.push(`${key}: override removed`);
      changedCount++;
      continue;
    }
    if (!inBefore && inAfter) {
      detail.push(`${key}: ${formatOverride(a[key])}`);
      changedCount++;
      continue;
    }
    if (!deepEqual(b[key], a[key])) {
      detail.push(`${key}: ${formatOverride(a[key])}`);
      changedCount++;
    }
  }

  return {
    summary: `${changedCount} override(s) changed`,
    detail: detail.length ? detail : undefined,
  };
}

// ---------------------------------------------------------------------------
// core.sandbox.rest.mapping.*
// ---------------------------------------------------------------------------

function describeChannelMapping(entry: CatalogEntry, before: unknown, after: unknown): string {
  const channel = entry.key.split(".").pop();
  return `channel ${channel}: ${formatScalar(before)} → ${formatScalar(after)}`;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export function describeChange(entry: CatalogEntry, before: unknown, after: unknown): ChangeLine {
  const base = { key: entry.key, title: entry.title, applies: entry.applies };

  if (entry.key === "core.mcp.servers") {
    return { ...base, ...describeServerMap(before, after) };
  }
  if (entry.key === "core.agents.definitions") {
    return { ...base, ...describeDefinitionsMap(before, after) };
  }
  if (entry.key === "core.agents.profiles") {
    return { ...base, ...describeProfilesMap(before, after) };
  }
  if (entry.key === "core.agents.profile") {
    return { ...base, summary: `active profile: ${formatScalar(before)} → ${formatScalar(after)}` };
  }
  if (entry.key === "core.llm.agents") {
    return { ...base, ...describeLlmAgentsMap(before, after) };
  }
  if (entry.key.startsWith("core.sandbox.rest.mapping.")) {
    return { ...base, summary: describeChannelMapping(entry, before, after) };
  }

  if (entry.secret) {
    const isCleared = after === null || after === undefined || after === "";
    return { ...base, summary: isCleared ? "cleared" : "new value" };
  }

  if (entry.type === "bool") {
    return { ...base, summary: `${formatBool(before)} → ${formatBool(after)}` };
  }

  if (entry.type === "list" || entry.type === "dict" || entry.type === "json") {
    return { ...base, ...describeCollection(before, after) };
  }

  return { ...base, summary: `${formatScalar(before)} → ${formatScalar(after)}` };
}
