/**
 * A block's tool declarations as stored: its changes over what it ships, per tool.
 *
 * The API stores a built-in block's tool declarations one tool at a time
 * (`maljan.core.tool_declarations.tool_facts_changes`): nothing for a tool
 * left as shipped, the changed fields of an edited one, `null` for a shipped
 * tool removed, the whole declaration of a tool the block does not ship. The
 * declarations in force are the shipped ones with those changes over them
 * (`merge_tool_facts`). The editor shows and edits what is in force and
 * stages the changes; with nothing shipped (a server an operator added) the
 * two are the same map. Nothing in this file names a tool or a server.
 */

import type { ToolDeclarationFields, ToolFactsEntry } from "@/types/settings";
import { sameJson } from "./declarationFields";

/** A stored change of one tool: its changed fields, its whole declaration, or `null`. */
export type ToolFactsChange = Partial<ToolFactsEntry> | Record<string, unknown> | null;
export type ToolFactsChanges = Record<string, ToolFactsChange>;
type Declarations = Record<string, Record<string, unknown>>;

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** The declarations in force: `shipped` with `changes` over it, one tool at a time. */
export function mergeToolFacts(
  shipped: Declarations,
  changes: ToolFactsChanges | undefined
): Record<string, ToolFactsEntry> {
  const held = changes ?? {};
  const out: Record<string, ToolFactsEntry> = {};
  for (const [tool, facts] of Object.entries(shipped)) {
    if (!Object.prototype.hasOwnProperty.call(held, tool)) {
      out[tool] = facts as ToolFactsEntry;
      continue;
    }
    const change = held[tool];
    if (change === null) continue;
    out[tool] = (isObject(change) ? { ...facts, ...change } : change) as ToolFactsEntry;
  }
  for (const [tool, change] of Object.entries(held)) {
    if (!Object.prototype.hasOwnProperty.call(shipped, tool) && change !== null) {
      out[tool] = change as ToolFactsEntry;
    }
  }
  return out;
}

/** The default of a declaration field, from the served split; `undefined` when unknown. */
function fieldDefault(name: string, fields: ToolDeclarationFields | null): unknown {
  if (fields === null) return undefined;
  if (name === "kind") return "";
  if (Object.prototype.hasOwnProperty.call(fields.kind_free, name)) return fields.kind_free[name];
  if (Object.prototype.hasOwnProperty.call(fields.kind_dependent, name)) {
    return fields.kind_dependent[name];
  }
  return undefined;
}

/** What `inForce` changes of `shipped`, per tool: the form the editor stages.
 *
 *  A field an edited shipped tool no longer names is its default (the
 *  operator deleted it), when the served split says what the default is;
 *  otherwise it keeps following the shipped value. */
export function toolFactsChanges(
  inForce: Record<string, unknown>,
  shipped: Declarations,
  fields: ToolDeclarationFields | null = null
): ToolFactsChanges {
  const out: ToolFactsChanges = {};
  for (const [tool, facts] of Object.entries(shipped)) {
    if (!Object.prototype.hasOwnProperty.call(inForce, tool)) {
      out[tool] = null;
      continue;
    }
    const held = inForce[tool];
    if (!isObject(held)) {
      if (!sameJson(held, facts)) out[tool] = held as ToolFactsChange;
      continue;
    }
    const changed: Record<string, unknown> = {};
    for (const [name, value] of Object.entries(held)) {
      if (!Object.prototype.hasOwnProperty.call(facts, name) || !sameJson(value, facts[name])) {
        changed[name] = value;
      }
    }
    for (const name of Object.keys(facts)) {
      if (Object.prototype.hasOwnProperty.call(held, name)) continue;
      const fallback = fieldDefault(name, fields);
      if (fallback !== undefined && !sameJson(fallback, facts[name])) changed[name] = fallback;
    }
    if (Object.keys(changed).length > 0) out[tool] = changed;
  }
  for (const [tool, held] of Object.entries(inForce)) {
    if (!Object.prototype.hasOwnProperty.call(shipped, tool)) out[tool] = held as ToolFactsChange;
  }
  return out;
}

/** One tool that carries an operator's change: edited, removed, or the operator's own. */
export interface ToolChange {
  tool: string;
  state: "changed" | "removed" | "added";
}

/** The tools `changes` makes a difference to, in the order they are named. */
export function changedTools(shipped: Declarations, changes: ToolFactsChanges | undefined): ToolChange[] {
  const out: ToolChange[] = [];
  for (const [tool, change] of Object.entries(changes ?? {})) {
    const ships = Object.prototype.hasOwnProperty.call(shipped, tool);
    if (!ships) {
      if (change !== null) out.push({ tool, state: "added" });
      continue;
    }
    if (change === null) {
      out.push({ tool, state: "removed" });
      continue;
    }
    const facts = shipped[tool];
    const merged = isObject(change) ? { ...facts, ...change } : change;
    if (!sameJson(merged, facts)) out.push({ tool, state: "changed" });
  }
  return out;
}

/** `changes` with one tool back as shipped (an operator's own tool is dropped). */
export function resetTool(changes: ToolFactsChanges | undefined, tool: string): ToolFactsChanges {
  const out: ToolFactsChanges = { ...(changes ?? {}) };
  delete out[tool];
  return out;
}
