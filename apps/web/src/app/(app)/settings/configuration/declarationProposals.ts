/**
 * The declarations a server probe proposes for the tools nobody declared
 * (`maljan.core.declaration_proposals`), and what accepting one stages.
 *
 * A proposal is data the server's own schemas and answers suggest, shown to
 * an admin. Nothing here saves anything: accepting a field or a whole tool
 * writes it into the staged server entry exactly as typing it into the
 * declaration box would, and Apply saves it through the settings path every
 * declaration takes. A field is staged with only the fields it needs to
 * validate (`requires`: a row field needs `rows`); a kind is never staged
 * unless it is the field accepted, so a tool keeps every reading an
 * undeclared tool gets until a kind is accepted for it. What is staged is
 * read from and written as the declarations in force, the entry's changes
 * over what the server ships (`toolFactsChanges`).
 */

import type {
  ErrorPatternEntry,
  McpServerEntry,
  ProbeResult,
  SampleOpenEntry,
  ToolDeclarationFields,
  ToolFactsEntry,
} from "@/types/settings";
import { isSet, sameJson } from "./declarationFields";
import { fieldDefault, mergeToolFacts, toolFactsChanges } from "./toolFactsChanges";

export type Confidence = "high" | "medium" | "low";

export interface ProposedField {
  value: unknown;
  evidence: string[];
  confidence: Confidence;
  requires?: string[];
}

export interface ToolProposal {
  facts: ToolFactsEntry;
  fields: Record<string, ProposedField>;
  notes?: string[];
}

/** One harmless call the probe would make once the admin confirms it. */
export interface PlannedCall {
  tool: string;
  arguments: Record<string, unknown>;
  /** The tool may reach a service of its own (its server does not say otherwise). */
  remote: boolean;
  /** The call would carry this server's credential (its declaration needs one). */
  credential: boolean;
  /** What the call is made without: the auth token and the environment
   *  variables the server does not declare non-secret, each named. */
  withheld: string[];
}

export interface Proposals {
  v: number;
  tools: Record<string, ToolProposal>;
  server: Record<string, ProposedField>;
  probed?: Record<string, string>;
  planned?: PlannedCall[];
  failed?: Record<string, string>;
  /** What the probe says of the server as a whole, such as the hint that its
   *  tools' rows read like a sandbox run's while it is not declared one. */
  notes?: string[];
}

const CONFIDENCES = new Set(["high", "medium", "low"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((e): e is string => typeof e === "string") : [];
}

function readField(value: unknown): ProposedField | null {
  if (!isRecord(value)) return null;
  const confidence = typeof value.confidence === "string" && CONFIDENCES.has(value.confidence)
    ? (value.confidence as Confidence)
    : "low";
  const requires = Array.isArray(value.requires) ? strings(value.requires) : undefined;
  return {
    value: value.value,
    evidence: strings(value.evidence),
    confidence,
    ...(requires && requires.length ? { requires } : {}),
  };
}

/** An empty map keyed by tool name, with no prototype, so a tool named like one
 *  of `Object.prototype`'s keys (`__proto__`) is an own key like any other. */
function toolMap<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

function readStringMap(value: unknown): Record<string, string> {
  const out = toolMap<string>();
  for (const [key, said] of Object.entries(isRecord(value) ? value : {})) {
    if (typeof said === "string") out[key] = said;
  }
  return out;
}

/** The proposals a probe result carries, or `null`; a part of an odd shape is left out. */
export function readProposals(result: ProbeResult | null | undefined): Proposals | null {
  const details = result?.details as { proposals?: unknown } | null | undefined;
  const raw = details?.proposals;
  if (!isRecord(raw) || !isRecord(raw.tools)) return null;
  const tools = toolMap<ToolProposal>();
  for (const [name, held] of Object.entries(raw.tools)) {
    if (!isRecord(held) || !isRecord(held.facts)) continue;
    if (held.facts.kind !== undefined && typeof held.facts.kind !== "string") continue;
    const fields: Record<string, ProposedField> = {};
    for (const [field, value] of Object.entries(isRecord(held.fields) ? held.fields : {})) {
      const read = readField(value);
      if (read) fields[field] = read;
    }
    const notes = Array.isArray(held.notes) ? strings(held.notes) : undefined;
    tools[name] = { facts: held.facts as ToolFactsEntry, fields, ...(notes ? { notes } : {}) };
  }
  const server: Record<string, ProposedField> = {};
  for (const [field, value] of Object.entries(isRecord(raw.server) ? raw.server : {})) {
    const read = readField(value);
    if (read) server[field] = read;
  }
  const planned: PlannedCall[] = [];
  for (const call of Array.isArray(raw.planned) ? raw.planned : []) {
    if (!isRecord(call) || typeof call.tool !== "string" || !isRecord(call.arguments)) continue;
    planned.push({
      tool: call.tool,
      arguments: call.arguments,
      remote: call.remote !== false,
      credential: call.credential === true,
      withheld: strings(call.withheld),
    });
  }
  const probed = readStringMap(raw.probed);
  const failed = readStringMap(raw.failed);
  const notes = strings(raw.notes);
  return {
    v: typeof raw.v === "number" ? raw.v : 1,
    tools,
    server,
    ...(Object.keys(probed).length ? { probed } : {}),
    ...(planned.length ? { planned } : {}),
    ...(Object.keys(failed).length ? { failed } : {}),
    ...(notes.length ? { notes } : {}),
  };
}

/** A proposed value as one line of text, for showing it (React escapes it). */
export function showValue(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

/** The fields one accepted field brings with it, itself last, each once. */
export function withRequired(proposal: ToolProposal, field: string): string[] {
  const out: string[] = [];
  const visit = (name: string, seen: Set<string>) => {
    if (seen.has(name) || !(name in proposal.fields)) return;
    seen.add(name);
    for (const needed of proposal.fields[name].requires ?? []) visit(needed, seen);
    out.push(name);
  };
  visit(field, new Set());
  return out;
}

/**
 * What the panel reads a server's tool declarations against: what the server
 * ships (`{}` for a server an operator added) and the served split of a
 * declaration's fields, whose defaults say what a field left out reads as.
 */
export interface Declared {
  shipped: Record<string, Record<string, unknown>>;
  fields: ToolDeclarationFields | null;
}

const NOTHING_SHIPPED: Declared = { shipped: {}, fields: null };

/** `tool`'s declaration in force: the shipped one with the entry's change over
 *  it; `undefined` for a tool nothing declares or the operator removed. */
function inForce(server: McpServerEntry, tool: string, declared: Declared): Record<string, unknown> | undefined {
  return mergeToolFacts(declared.shipped, server.tool_facts)[tool] as Record<string, unknown> | undefined;
}

/** Whether `facts` sets `name`: present and, where the split says its default, not at it. */
function holds(facts: Record<string, unknown>, name: string, fields: ToolDeclarationFields | null): boolean {
  if (!Object.prototype.hasOwnProperty.call(facts, name)) return false;
  const fallback = fieldDefault(name, fields);
  return fallback === undefined || isSet(facts[name], fallback);
}

/**
 * The entry change that puts `facts` in force as `tool`'s declaration.
 *
 * Staged as every other edit of the declarations is: the changes of what is
 * in force over what ships (`toolFactsChanges`), marked. A field the server
 * ships for the tool that `facts` does not name is staged at its default, so
 * what is in force is `facts` alone, never `facts` over the shipped
 * declaration of a tool the operator removed.
 */
function staged(
  server: McpServerEntry,
  tool: string,
  facts: Record<string, unknown>,
  declared: Declared,
): Partial<McpServerEntry> {
  const all = { ...mergeToolFacts(declared.shipped, server.tool_facts), [tool]: facts };
  return {
    tool_facts: toolFactsChanges(all, declared.shipped, declared.fields) as McpServerEntry["tool_facts"],
  };
}

/** The fields accepting `field` would add beside it, where the declaration in force lacks them. */
export function alsoStaged(
  server: McpServerEntry,
  tool: string,
  proposal: ToolProposal,
  field: string,
  declared: Declared = NOTHING_SHIPPED,
): string[] {
  const held = inForce(server, tool, declared) ?? {};
  return withRequired(proposal, field).filter(
    (name) => name !== field && !holds(held, name, declared.fields),
  );
}

/**
 * The server entry with one proposed field of `tool` accepted.
 *
 * Read from the tool's declaration in force (none for a tool nobody declares
 * or the operator removed). A field it already holds is replaced; the fields
 * it requires are added only where it does not set them yet, so accepting
 * `places` never overwrites a `rows` the operator wrote. No kind is added
 * unless `kind` is the field accepted.
 */
export function acceptField(
  server: McpServerEntry,
  tool: string,
  proposal: ToolProposal,
  field: string,
  declared: Declared = NOTHING_SHIPPED,
): Partial<McpServerEntry> {
  const next: Record<string, unknown> = { ...(inForce(server, tool, declared) ?? {}) };
  for (const name of withRequired(proposal, field)) {
    if (name === field || !holds(next, name, declared.fields)) next[name] = proposal.fields[name].value;
  }
  return staged(server, tool, next, declared);
}

/** Whether accepting the whole tool would stage anything. */
export function hasProposal(proposal: ToolProposal): boolean {
  return Object.keys(proposal.facts).length > 0;
}

/** The server entry with `tool`'s whole proposed declaration accepted, replacing its own:
 *  in force it is the proposal alone. */
export function acceptTool(
  server: McpServerEntry,
  tool: string,
  proposal: ToolProposal,
  declared: Declared = NOTHING_SHIPPED,
): Partial<McpServerEntry> {
  if (!hasProposal(proposal)) return {};
  return staged(server, tool, { ...proposal.facts }, declared);
}

/**
 * The server entry with one proposed server-wide field accepted.
 *
 * Error patterns are added beside the ones the server already declares (a
 * pattern already there is not added twice); auto-name prefixes likewise.
 */
export function acceptServerField(
  server: McpServerEntry,
  field: string,
  proposed: ProposedField,
): Partial<McpServerEntry> {
  if (field === "error_patterns" && Array.isArray(proposed.value)) {
    const held = server.error_patterns ?? [];
    const seen = new Set(held.map((p) => JSON.stringify(p)));
    const added = (proposed.value as ErrorPatternEntry[]).filter(
      (p) => !seen.has(JSON.stringify(p)),
    );
    return { error_patterns: [...held, ...added] };
  }
  if (field === "auto_name_prefixes" && Array.isArray(proposed.value)) {
    const held = server.auto_name_prefixes ?? [];
    const added = (proposed.value as string[]).filter((p) => !held.includes(p));
    return { auto_name_prefixes: [...held, ...added] };
  }
  if (field === "sample_open" && isRecord(proposed.value)) {
    // Fills only the fields the server leaves empty: a declared field stays.
    const held: SampleOpenEntry = { ...EMPTY_SAMPLE_OPEN, ...(server.sample_open ?? {}) };
    const filled = { ...held };
    for (const key of Object.keys(EMPTY_SAMPLE_OPEN) as (keyof SampleOpenEntry)[]) {
      const value = proposed.value[key];
      if (!held[key] && typeof value === "string") filled[key] = value;
    }
    return { sample_open: filled };
  }
  return {};
}

const EMPTY_SAMPLE_OPEN: SampleOpenEntry = {
  open_tool: "",
  path_argument: "",
  name_field: "",
  select_tool: "",
  select_argument: "",
  analyse_tool: "",
  analyse_argument: "",
};

/** Whether `tool`'s declaration in force holds `field` with exactly the proposed value. */
export function isAccepted(
  server: McpServerEntry,
  tool: string,
  field: string,
  proposal: ToolProposal,
  declared: Declared = NOTHING_SHIPPED,
): boolean {
  const held = inForce(server, tool, declared);
  if (!held || !(field in held) || !(field in proposal.fields)) return false;
  return sameJson(held[field], proposal.fields[field].value);
}

/** How many tools the panel lists open before it starts closed. */
export const OPEN_UP_TO = 5;
