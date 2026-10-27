import { describeDebate } from "./debateOptions";
/**
 * Turns one staged catalog change into a human-readable review line for the
 * changes bar and the guide's review step. Pure and side-effect free: no
 * network, no React. `describeChange` never renders a secret value — the
 * masking rules below are the single place that decides what a viewer sees
 * for a token or a `secret`-typed leaf.
 */
import { AGENT_DEFINITIONS_KEY } from "./agentStaging";
import { countLabel } from "@/lib/report-utils";
import type {
  AgentDefinitionEntry,
  CatalogEntry,
  ProfileEntry,
  StageEntry,
  ToolDeclarationFields,
} from "@/types/settings";
import type { AgentLLMOverride } from "./AgentDefinitionsEditor";
import { deepEqual } from "./deepEqual";
import { ENRICHMENT_SOURCES_SPEC, REPORT_FORMATS_SPEC, type RowsSpec } from "./recordRows";
import { shippedToolFactsOf } from "@/lib/providerFacts";
import { toolFactsDiff, type ToolFactsDiff } from "./toolFactsChanges";

export interface ChangeLine {
  key: string;
  title: string;
  summary: string;
  detail?: string[];
  applies: CatalogEntry["applies"];
}

const MAX_SCALAR_LENGTH = 60;

/** Renders a scalar for a `before → after` line: `unset` for null/undefined,
 *  `""` for the empty string (so an empty side still shows), plain (unquoted)
 *  text for other strings, `String()` for everything else. Long strings are
 *  cut to 60 chars with an ellipsis. Exported so tests (and any other
 *  scalar-rendering call site) share one rule. */
export function formatScalar(v: unknown): string {
  if (v === null || v === undefined) return "unset";
  if (v === "") return '""';
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
 *  key order. Exported so `importPreview.ts` shares this one rule instead of
 *  carrying its own copy. */
export { deepEqual };

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

const MAX_RECORD_LENGTH = 80;

/** Field names that hold a secret in a record of a collection: the ones the
 *  record editors mark, plus any name that reads as a credential, so a record
 *  the editors do not know never prints one. */
const SECRET_NAME = /(api_?key|token|secret|password|passwd)/i;

function secretFieldsOf(entry: CatalogEntry): Set<string> {
  const spec: RowsSpec | null =
    entry.editor === "enrichment_sources"
      ? ENRICHMENT_SOURCES_SPEC
      : entry.editor === "report_formats"
        ? REPORT_FORMATS_SPEC
        : null;
  return new Set((spec?.fields ?? []).filter((f) => f.secret).map((f) => f.name));
}

const isPlainRecord = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);

const isSecretField = (name: string, secrets: Set<string>) =>
  secrets.has(name) || SECRET_NAME.test(name);

/** The value with every secret field's value left out. */
function redacted(v: unknown, secrets: Set<string>): unknown {
  if (Array.isArray(v)) return v.map((x) => redacted(x, secrets));
  if (!isPlainRecord(v)) return v;
  const out: Record<string, unknown> = {};
  for (const [k, x] of Object.entries(v)) {
    out[k] = isSecretField(k, secrets) ? (hasToken(x) ? "(secret)" : x) : redacted(x, secrets);
  }
  return out;
}

/** A list or dict entry as one short piece of text: a scalar as `formatScalar`
 *  has it, a record or list as compact JSON cut at 80 characters. */
function formatEntryValue(v: unknown, secrets: Set<string>): string {
  if (v === null || typeof v !== "object") return formatScalar(v);
  const text = JSON.stringify(redacted(v, secrets));
  return text.length > MAX_RECORD_LENGTH ? `${text.slice(0, MAX_RECORD_LENGTH)}…` : text;
}

/** What changed in one secret field, never its value. */
function secretChange(name: string, before: unknown, after: unknown): string {
  if (after === null || after === undefined || after === "") return `${name} cleared`;
  return hasToken(before) ? `${name} new value` : `${name} set`;
}

/** The fields that differ between two records, `field old → new`; a changed
 *  value that is itself a record or list reads as compact JSON. */
function describeRecordFields(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
  secrets: Set<string>
): string {
  const parts: string[] = [];
  for (const name of collectKeys(before, after)) {
    if (deepEqual(before[name], after[name])) continue;
    parts.push(
      isSecretField(name, secrets)
        ? secretChange(name, before[name], after[name])
        : `${name} ${formatEntryValue(before[name], secrets)} → ${formatEntryValue(after[name], secrets)}`
    );
  }
  return parts.join("; ");
}

function describeListChange(before: unknown[], after: unknown[], secrets: Set<string>): {
  summary: string;
  detail?: string[];
} {
  const added = after.filter((v) => !before.some((b) => deepEqual(b, v)));
  const removed = before.filter((v) => !after.some((a) => deepEqual(a, v)));
  const detail = [
    ...added.map((v) => `+ ${formatEntryValue(v, secrets)}`),
    ...removed.map((v) => `− ${formatEntryValue(v, secrets)}`),
  ];
  return {
    summary: `+${added.length} −${removed.length} entries`,
    detail: detail.length ? detail : undefined,
  };
}

function describeDictChange(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
  secrets: Set<string>
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
      detail.push(`+ ${key}: ${formatEntryValue(after[key], secrets)}`);
    } else if (inBefore && !inAfter) {
      removed++;
      detail.push(`− ${key}: ${formatEntryValue(before[key], secrets)}`);
    } else if (!deepEqual(before[key], after[key])) {
      detail.push(
        isPlainRecord(before[key]) && isPlainRecord(after[key])
          ? `~ ${key}: ${describeRecordFields(before[key], after[key], secrets)}`
          : `~ ${key}: ${formatEntryValue(before[key], secrets)} → ${formatEntryValue(after[key], secrets)}`
      );
    }
  }
  return {
    summary: `+${added} −${removed} entries`,
    detail: detail.length ? detail : undefined,
  };
}

function describeCollection(entry: CatalogEntry, before: unknown, after: unknown): {
  summary: string;
  detail?: string[];
} {
  const secrets = secretFieldsOf(entry);
  if (Array.isArray(before) || Array.isArray(after)) {
    return describeListChange(
      Array.isArray(before) ? before : [],
      Array.isArray(after) ? after : [],
      secrets
    );
  }
  return describeDictChange(asRecord(before), asRecord(after), secrets);
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
  "agents",
  "call_timeout_seconds",
  // The server's declaration (`maljan.core.tool_declarations`).
  "sample_open",
  "sample_mount",
  "work_dir",
  "error_patterns",
  "roles",
  "prompt_fragment",
  "required_env_allow",
  "variable_names",
  "reads_staged_sample",
  "platform_owned",
  "trusts_served_declaration",
  "auto_name_prefixes",
  "reference_urls",
  "tool_facts",
  "credential_bootstrap",
  "launcher_depth",
  "prepass_tools",
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

/** The server map, one server at a time. A server's `tool_facts` are compared
 *  per tool as they are in force (`toolFactsDiff` over what the server ships,
 *  read off the map's catalog entry), so a value written in another form that
 *  puts the same tools in force is no change. */
function describeServerMap(
  entry: CatalogEntry,
  before: unknown,
  after: unknown,
  fields: ToolDeclarationFields | null
): {
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
    const changed: string[] = [];
    let toolLines: string[] = [];
    for (const field of SERVER_FIELDS) {
      if (deepEqual(bs[field], as[field])) continue;
      if (field === "tool_facts") {
        const diff = toolFactsDiff(shippedToolFactsOf(entry, key), bs[field], as[field], fields);
        if (diff.length === 0) continue;
        // Each tool that changes in force is named, as on a block's own
        // declarations, under the server's line.
        toolLines = diff.map((d) => `${key}: tool ${describeToolLine(d)}`);
      }
      changed.push(field);
    }
    if (!deepEqual(bs.tools, as.tools)) {
      const beforeCount =
        bs.tools === null || bs.tools === undefined ? "all" : (bs.tools as unknown[]).length;
      const afterCount =
        as.tools === null || as.tools === undefined ? "all" : (as.tools as unknown[]).length;
      changed.push(`tools (${beforeCount} → ${afterCount})`);
    }
    const tokenChange = describeTokenChange(bs.auth_token, as.auth_token);
    if (tokenChange) changed.push(tokenChange);

    // A flip that happens alongside other edits joins the `changed:` list
    // rather than being dropped for them: "disabled" is usually the most
    // consequential half of such a change.
    if (enabledChanged) changed.unshift(as.enabled ? "enabled" : "disabled");

    if (changed.length === 1 && enabledChanged) {
      detail.push(`${key}: ${as.enabled ? "enabled" : "disabled"}`);
      changedCount++;
    } else if (changed.length > 0) {
      detail.push(`${key}: changed: ${changed.join(", ")}`);
      changedCount++;
    }
    detail.push(...toolLines);
  }

  return {
    summary: `${countLabel(changedCount, "server")} changed`,
    detail: detail.length ? detail : undefined,
  };
}

// ---------------------------------------------------------------------------
// core.agents.definitions
// ---------------------------------------------------------------------------

/**
 * Every field of a definition the review names, and what it calls it.
 *
 * `enabled` is not here: it is drawn as its own word ("enabled" / "disabled")
 * a few lines below, because a switch reads better as a verb than as a field
 * that changed. Everything else on `AgentDefinitionEntry` belongs here — a
 * field that is missing produces a review row reading "0 agents changed" over
 * an edit that will be saved, which is the untruth this panel exists to
 * remove. `__tests__/describeChange.test.ts` fails when the two drift apart.
 */
export const DEFINITION_FIELDS: [keyof AgentDefinitionEntry, string][] = [
  ["prompt", "prompt"],
  ["tools", "tools"],
  ["static_provider", "static provider"],
  ["label", "label"],
  ["role", "role"],
  ["max_steps", "steps per loop"],
  ["timeout_seconds", "seconds per loop"],
  ["tab", "console tab"],
  ["data_sources", "input data"],
  ["chunk_boundary", "chunk boundaries"],
  ["attck_techniques", "ATT&CK technique line"],
];

/** A definition field as the settings model reads it: an absent ATT&CK
 *  technique switch is on, so an explicit `true` and no field are the same. */
function comparableField(def: AgentDefinitionEntry, field: keyof AgentDefinitionEntry): unknown {
  if (field === "attck_techniques") return def.attck_techniques !== false;
  return def[field];
}

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
      if (!deepEqual(comparableField(bs, field), comparableField(as, field))) fields.push(label);
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
    summary: `${countLabel(changedCount, "agent")} changed`,
    detail: detail.length ? detail : undefined,
  };
}

// ---------------------------------------------------------------------------
// core.agents.profiles / core.agents.profile
// ---------------------------------------------------------------------------

function stageSummary(stage: StageEntry): string {
  const parts: string[] = [stage.kind];
  if (stage.agents.length) parts.push(stage.agents.join("+"));
  if (stage.depends_on.length) parts.push(`after ${stage.depends_on.join("+")}`);
  if (stage.when.trim()) parts.push(`when ${stage.when.trim()}`);
  return parts.join(", ");
}

function describeStage(profile: string, before: StageEntry, after: StageEntry): string[] {
  const lines: string[] = [];
  const field = `${profile}/${after.key}`;
  if (before.kind !== after.kind) lines.push(`${field}: kind ${before.kind} → ${after.kind}`);
  if (!deepEqual(before.agents, after.agents)) {
    const gained = after.agents.filter((a) => !before.agents.includes(a));
    const lost = before.agents.filter((a) => !after.agents.includes(a));
    lines.push(
      gained.length || lost.length
        ? `${field}: agents changed (+${gained.length} −${lost.length})`
        : `${field}: agents reordered (${after.agents.join(", ")})`
    );
  }
  if (!deepEqual(before.depends_on, after.depends_on)) {
    lines.push(`${field}: depends on ${after.depends_on.join(", ") || "nothing"}`);
  }
  if (before.when !== after.when) {
    lines.push(`${field}: condition ${before.when || "always"} → ${after.when || "always"}`);
  }
  if (before.mode !== after.mode) lines.push(`${field}: runs ${after.mode ?? "auto"}`);
  if (before.inject_upstream !== after.inject_upstream) {
    lines.push(`${field}: upstream findings ${after.inject_upstream}`);
  }
  if (before.builtin_tools !== after.builtin_tools) {
    lines.push(`${field}: built-in tools ${after.builtin_tools ? "on" : "off"}`);
  }
  if (!deepEqual(before.debate, after.debate)) {
    lines.push(
      `${field}: ${describeDebate(after.debate)}`
    );
  }
  if (before.label !== after.label) lines.push(`${field}: label changed`);
  return lines;
}

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
    const beforeStages = bp.stages ?? [];
    const afterStages = ap.stages ?? [];
    const beforeByKey = new Map(beforeStages.map((s) => [s.key, s]));
    const afterByKey = new Map(afterStages.map((s) => [s.key, s]));

    // A team's stages are its shape, so an added, removed or reordered stage
    // is reported as such before any per-stage field is: an operator who moved
    // the dynamic stage after the reversing stage should read that sentence,
    // not four lines about dependency lists.
    const lines: string[] = [];
    for (const stage of afterStages) {
      if (!beforeByKey.has(stage.key)) lines.push(`${key}/${stage.key}: added (${stageSummary(stage)})`);
    }
    for (const stage of beforeStages) {
      if (!afterByKey.has(stage.key)) lines.push(`${key}/${stage.key}: removed`);
    }
    const beforeOrder = beforeStages.filter((s) => afterByKey.has(s.key)).map((s) => s.key);
    const afterOrder = afterStages.filter((s) => beforeByKey.has(s.key)).map((s) => s.key);
    if (!deepEqual(beforeOrder, afterOrder)) {
      lines.push(`${key}: stages reordered (${afterStages.map((s) => s.key).join(" → ")})`);
    }
    for (const stage of afterStages) {
      const previous = beforeByKey.get(stage.key);
      if (previous) lines.push(...describeStage(key, previous, stage));
    }
    if (bp.label !== ap.label) lines.push(`${key}: label changed`);

    if (lines.length > 0) {
      detail.push(...lines);
      changedCount++;
    }
  }

  return {
    summary: `${countLabel(changedCount, "team")} changed`,
    detail: detail.length ? detail : undefined,
  };
}

// ---------------------------------------------------------------------------
// core.llm.agents
// ---------------------------------------------------------------------------

function formatOverride(o: AgentLLMOverride): string {
  // An entry holding only its ceilings names no model of its own.
  let base = o.provider || o.model ? `${o.provider}/${o.model}` : "its usual model";
  if (o.base_url) base = `${base} @ ${o.base_url}`;
  if (o.effort) base = `${base} (effort ${o.effort})`;
  if (o.temperature !== null && o.temperature !== undefined) {
    base = `${base} (temp ${o.temperature})`;
  }
  const fallbacks = (o.fallbacks ?? []).map(
    (f) => `${f.provider}/${f.model}${f.effort ? ` (effort ${f.effort})` : ""}`,
  );
  const listed = fallbacks.length ? `${base}, then ${fallbacks.join(", then ")}` : base;
  const ceilings = [
    o.max_spend_usd != null ? `${o.max_spend_usd} USD` : "",
    o.max_unpriced_tokens != null ? `${o.max_unpriced_tokens} unpriced tokens` : "",
  ].filter(Boolean);
  return ceilings.length ? `${listed} (ceiling ${ceilings.join(", ")})` : listed;
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
    summary: `${countLabel(changedCount, "override")} changed`,
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
// A block's tool declarations (editor "tool_facts")
// ---------------------------------------------------------------------------

const TOOL_STATE_WORDS: Record<ToolFactsDiff["state"], string> = {
  changed: "changed",
  reset: "reset to shipped",
  removed: "removed",
  added: "added",
};

const isStructured = (v: unknown) => v !== null && typeof v === "object";

/** One tool's line: its state, and for a changed tool each field that differs
 *  (a scalar one with its value before and after, a structured one by name). */
function describeToolLine({ tool, state, fields }: ToolFactsDiff): string {
  if (state !== "changed" || !fields?.length) return `${tool}: ${TOOL_STATE_WORDS[state]}`;
  const parts = fields.map(({ name, before, after }) =>
    isStructured(before) || isStructured(after)
      ? name
      : `${name} ${formatScalar(before)} → ${formatScalar(after)}`
  );
  return `${tool}: changed: ${parts.join(", ")}`;
}

/** A block's tool declarations, compared per tool as they are in force: the
 *  catalog default is what the block ships, and the stored and staged values
 *  are read as the API reads them (`toolFactsDiff`). Never names the mark or
 *  a tool both sides hold as shipped. */
export function describeToolFacts(
  entry: CatalogEntry,
  before: unknown,
  after: unknown,
  fields: ToolDeclarationFields | null = null
): { summary: string; detail?: string[] } {
  const shipped = (
    entry.default && typeof entry.default === "object" && !Array.isArray(entry.default)
      ? entry.default
      : {}
  ) as Record<string, Record<string, unknown>>;
  const diff = toolFactsDiff(shipped, before, after, fields);
  if (diff.length === 0) return { summary: "no tool changes" };
  const counts = (["changed", "reset", "removed", "added"] as const)
    .map((state) => [state, diff.filter((d) => d.state === state).length] as const)
    .filter(([, n]) => n > 0)
    .map(([state, n]) => `${countLabel(n, "tool")} ${TOOL_STATE_WORDS[state]}`);
  return { summary: counts.join(", "), detail: diff.map(describeToolLine) };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export function describeChange(
  entry: CatalogEntry,
  before: unknown,
  after: unknown,
  fields: ToolDeclarationFields | null = null
): ChangeLine {
  const base = { key: entry.key, title: entry.title, applies: entry.applies };

  if (entry.editor === "tool_facts") {
    return { ...base, ...describeToolFacts(entry, before, after, fields) };
  }

  if (entry.key === "core.mcp.servers") {
    return { ...base, ...describeServerMap(entry, before, after, fields) };
  }
  if (entry.key === AGENT_DEFINITIONS_KEY) {
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
    return { ...base, ...describeCollection(entry, before, after) };
  }

  return { ...base, summary: `${formatScalar(before)} → ${formatScalar(after)}` };
}
