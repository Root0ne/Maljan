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
 *
 * A map of changes carries a mark (`"": "changes"`, under a key no tool can
 * be named by: a tool's name is never empty), which the API stores so it
 * never has to guess whether a map holds changes or was stored whole by an
 * earlier release. The API serves every stored map marked; the editor keeps
 * the mark on what it stages and never reads it as a tool.
 */

import type { ToolDeclarationFields, ToolFactsEntry } from "@/types/settings";
import { sameJson } from "./declarationFields";

/** The key and value that mark a map as a block's changes over what it ships
 *  (`maljan.core.tool_declarations.CHANGES_MARK` and `CHANGES_FORM`). */
export const CHANGES_MARK = "";
export const CHANGES_FORM = "changes";

/** A stored change of one tool: its changed fields, its whole declaration, or `null`. */
export type ToolFactsChange = Partial<ToolFactsEntry> | Record<string, unknown> | null;
export type ToolFactsChanges = Record<string, ToolFactsChange | typeof CHANGES_FORM>;
type Declarations = Record<string, Record<string, unknown>>;

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** An empty map keyed by tool name. It has no prototype, so a tool named like
 *  one of `Object.prototype`'s own keys (`__proto__`, which the API accepts)
 *  is an own key like any other, never the object's prototype. */
function toolMap<T>(): Record<string, T> {
  return Object.create(null) as Record<string, T>;
}

const owns = (map: object, key: string) => Object.prototype.hasOwnProperty.call(map, key);

/** The tools `changes` names and what it says of each, without the mark. */
export function withoutMark(
  changes: ToolFactsChanges | undefined | null
): Record<string, ToolFactsChange> {
  const out = toolMap<ToolFactsChange>();
  for (const [tool, change] of Object.entries(changes ?? {})) {
    if (tool === CHANGES_MARK && change === CHANGES_FORM) continue;
    out[tool] = change as ToolFactsChange;
  }
  return out;
}

/** `changes` marked as a block's changes over what it ships, as the API stores them.
 *  The mark always wins: whatever `changes` holds under the mark's key is no
 *  tool and is left out, as the API's `with_mark` leaves it out. */
export function withMark(changes: ToolFactsChanges | undefined | null): ToolFactsChanges {
  const out = toolMap<ToolFactsChange | typeof CHANGES_FORM>();
  out[CHANGES_MARK] = CHANGES_FORM;
  for (const [tool, change] of Object.entries(withoutMark(changes))) {
    if (tool !== CHANGES_MARK) out[tool] = change;
  }
  return out;
}

/** Whether `changes` names any tool (the mark alone names none). */
export function namesAnyTool(changes: ToolFactsChanges | undefined | null): boolean {
  return Object.keys(withoutMark(changes)).length > 0;
}

/** The declarations in force: `shipped` with `changes` over it, one tool at a time. */
export function mergeToolFacts(
  shipped: Declarations,
  changes: ToolFactsChanges | undefined
): Record<string, ToolFactsEntry> {
  const held = withoutMark(changes);
  const out = toolMap<ToolFactsEntry>();
  for (const [tool, facts] of Object.entries(shipped)) {
    if (!owns(held, tool)) {
      out[tool] = facts as ToolFactsEntry;
      continue;
    }
    const change = held[tool];
    if (change === null) continue;
    out[tool] = (isObject(change) ? { ...facts, ...change } : change) as ToolFactsEntry;
  }
  for (const [tool, change] of Object.entries(held)) {
    if (!owns(shipped, tool) && change !== null) {
      out[tool] = change as ToolFactsEntry;
    }
  }
  return out;
}

/** The default of a declaration field, from the served split; `undefined` when unknown. */
export function fieldDefault(name: string, fields: ToolDeclarationFields | null): unknown {
  if (fields === null) return undefined;
  if (name === "kind") return "";
  if (Object.prototype.hasOwnProperty.call(fields.kind_free, name)) return fields.kind_free[name];
  if (Object.prototype.hasOwnProperty.call(fields.kind_dependent, name)) {
    return fields.kind_dependent[name];
  }
  return undefined;
}

/** What `inForce` changes of `shipped`, per tool, marked: the form the editor stages.
 *
 *  A field an edited shipped tool no longer names is its default (the
 *  operator deleted it), when the served split says what the default is;
 *  otherwise it keeps following the shipped value. */
export function toolFactsChanges(
  inForce: Record<string, unknown>,
  shipped: Declarations,
  fields: ToolDeclarationFields | null = null
): ToolFactsChanges {
  const out = toolMap<ToolFactsChange | typeof CHANGES_FORM>();
  out[CHANGES_MARK] = CHANGES_FORM;
  for (const [tool, facts] of Object.entries(shipped)) {
    if (!owns(inForce, tool)) {
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
    if (!owns(shipped, tool)) out[tool] = held as ToolFactsChange;
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
  for (const [tool, change] of Object.entries(withoutMark(changes))) {
    const ships = owns(shipped, tool);
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

/** `changes` with one tool back as shipped (an operator's own tool is dropped), marked. */
export function resetTool(changes: ToolFactsChanges | undefined, tool: string): ToolFactsChanges {
  const out = withMark(changes);
  if (tool !== CHANGES_MARK) delete out[tool];
  return out;
}

/** Whether `value` is a map marked as a block's changes over what it ships. */
export function holdsChanges(value: unknown): boolean {
  return isObject(value) && value[CHANGES_MARK] === CHANGES_FORM;
}

/** A value of a block's `tool_facts` as its marked changes over `shipped`, read as the API
 *  reads it: a marked map as it is, one without the mark as the whole map
 *  (`inForceOf`), no value as none. */
export function asChanges(
  shipped: Declarations,
  value: unknown,
  fields: ToolDeclarationFields | null = null
): ToolFactsChanges | undefined {
  if (!isObject(value)) return undefined;
  if (holdsChanges(value)) return value as ToolFactsChanges;
  return toolFactsChanges(value, shipped, fields);
}

/** The declarations a value of a block's `tool_facts` puts in force, as the API reads it.
 *
 *  Marked, its changes over `shipped`; a map without the mark, whole (a
 *  shipped tool it does not name is removed, and a field a shipped tool's
 *  declaration leaves out is at its default when the served split says what
 *  that is); anything else (no value) is what ships. */
export function inForceOf(
  shipped: Declarations,
  value: unknown,
  fields: ToolDeclarationFields | null = null
): Record<string, ToolFactsEntry> {
  return mergeToolFacts(shipped, asChanges(shipped, value, fields));
}

/** One tool a change of a block's `tool_facts` makes a difference to. */
export interface ToolFactsDiff {
  tool: string;
  state: "changed" | "removed" | "added" | "reset";
  /** For a changed tool: each field that differs, with its value before and after. */
  fields?: { name: string; before: unknown; after: unknown }[];
}

/** What a change of a block's `tool_facts` from `before` to `after` does, per tool.
 *
 *  Both sides are read as the API reads them (`inForceOf`) and compared one
 *  tool at a time, so only the tools whose declaration in force changes are
 *  named: never the mark, never a tool both sides hold as shipped. A tool
 *  brought back to what ships is a reset. Time linear in the maps. */
export function toolFactsDiff(
  shipped: Declarations,
  before: unknown,
  after: unknown,
  fields: ToolDeclarationFields | null = null
): ToolFactsDiff[] {
  const was = inForceOf(shipped, before, fields);
  const now = inForceOf(shipped, after, fields);
  const has = owns;
  const tools = [...Object.keys(was), ...Object.keys(now).filter((tool) => !has(was, tool))];
  const out: ToolFactsDiff[] = [];
  for (const tool of tools) {
    if (!has(now, tool)) {
      out.push({ tool, state: "removed" });
      continue;
    }
    const asShipped = has(shipped, tool) && sameJson(now[tool], shipped[tool]);
    if (!has(was, tool)) {
      out.push({ tool, state: asShipped ? "reset" : "added" });
      continue;
    }
    if (sameJson(was[tool], now[tool])) continue;
    if (asShipped) {
      out.push({ tool, state: "reset" });
      continue;
    }
    const left = (isObject(was[tool]) ? was[tool] : {}) as Record<string, unknown>;
    const right = (isObject(now[tool]) ? now[tool] : {}) as Record<string, unknown>;
    const names = [...Object.keys(left), ...Object.keys(right).filter((name) => !has(left, name))];
    out.push({
      tool,
      state: "changed",
      fields: names
        .filter((name) => !sameJson(left[name], right[name]))
        .map((name) => ({ name, before: left[name], after: right[name] })),
    });
  }
  return out;
}
