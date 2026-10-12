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
 * undeclared tool gets until a kind is accepted for it.
 */

import type { ErrorPatternEntry, McpServerEntry, ProbeResult, ToolFactsEntry } from "@/types/settings";

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
}

export interface Proposals {
  v: number;
  tools: Record<string, ToolProposal>;
  server: Record<string, ProposedField>;
  probed?: Record<string, string>;
  planned?: PlannedCall[];
  failed?: Record<string, string>;
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

function readStringMap(value: unknown): Record<string, string> {
  const out: Record<string, string> = {};
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
  const tools: Record<string, ToolProposal> = {};
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
    });
  }
  const probed = readStringMap(raw.probed);
  const failed = readStringMap(raw.failed);
  return {
    v: typeof raw.v === "number" ? raw.v : 1,
    tools,
    server,
    ...(Object.keys(probed).length ? { probed } : {}),
    ...(planned.length ? { planned } : {}),
    ...(Object.keys(failed).length ? { failed } : {}),
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

/** The fields accepting `field` would add beside it, where the declaration lacks them. */
export function alsoStaged(
  server: McpServerEntry,
  tool: string,
  proposal: ToolProposal,
  field: string,
): string[] {
  const held = (server.tool_facts?.[tool] ?? {}) as Record<string, unknown>;
  return withRequired(proposal, field).filter((name) => name !== field && !(name in held));
}

/**
 * The server entry with one proposed field of `tool` accepted.
 *
 * A field the tool's declaration already holds is replaced; the fields it
 * requires are added only where the declaration does not hold them yet, so
 * accepting `places` never overwrites a `rows` the operator wrote. No kind
 * is added unless `kind` is the field accepted.
 */
export function acceptField(
  server: McpServerEntry,
  tool: string,
  proposal: ToolProposal,
  field: string,
): Partial<McpServerEntry> {
  const held = server.tool_facts?.[tool];
  const next: Record<string, unknown> = { ...(held ?? {}) };
  for (const name of withRequired(proposal, field)) {
    if (name === field || !(name in next)) next[name] = proposal.fields[name].value;
  }
  return { tool_facts: { ...(server.tool_facts ?? {}), [tool]: next as ToolFactsEntry } };
}

/** Whether accepting the whole tool would stage anything. */
export function hasProposal(proposal: ToolProposal): boolean {
  return Object.keys(proposal.facts).length > 0;
}

/** The server entry with `tool`'s whole proposed declaration accepted, replacing its own. */
export function acceptTool(
  server: McpServerEntry,
  tool: string,
  proposal: ToolProposal,
): Partial<McpServerEntry> {
  if (!hasProposal(proposal)) return {};
  return { tool_facts: { ...(server.tool_facts ?? {}), [tool]: { ...proposal.facts } } };
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
  return {};
}

/** Whether `tool`'s declaration already holds `field` with exactly the proposed value. */
export function isAccepted(
  server: McpServerEntry,
  tool: string,
  field: string,
  proposal: ToolProposal,
): boolean {
  const held = server.tool_facts?.[tool] as Record<string, unknown> | undefined;
  if (!held || !(field in held) || !(field in proposal.fields)) return false;
  return JSON.stringify(held[field]) === JSON.stringify(proposal.fields[field].value);
}

/** How many tools the panel lists open before it starts closed. */
export const OPEN_UP_TO = 5;
