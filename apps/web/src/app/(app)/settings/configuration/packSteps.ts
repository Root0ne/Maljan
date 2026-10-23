/**
 * The triage pack's steps as the console's step editor reads and writes them.
 *
 * Every rule here is read from what the API serves on the steps' entry
 * (`pack_step_vocabulary`, built by `core.pack_steps.step_vocabulary`): the
 * fields a step may set in the model's order, the pattern a whole step id is
 * read by and the ids it may not take, the placeholders an argument template
 * may name and the pattern a template string is read for them by, the routed
 * formats, the shipped steps, and what makes a declaration replace its
 * shipped step rather than change it field by field. The save validator stays
 * the one judge: what this module flags mirrors it, and only a row that cannot
 * be written at all (an argument with no name, or a name given twice) holds
 * Apply.
 *
 * What the form shows as in force is what the save applies: a step of one's
 * own, and one that replaces its shipped step, hold only what they set and
 * the fields' defaults; one that changes its shipped step holds the shipped
 * values it does not set.
 *
 * A step is written as it would be written by hand: only the fields set, in
 * the model's order, then every field the API does not know, as stored. A
 * step the form did not touch is kept as the very object it was.
 */

import type { McpServerEntry, PackStepField, PackStepVocabulary } from "@/types/settings";
import { deepEqual } from "./deepEqual";

/** One step as stored: a JSON object. */
export type StepValue = Record<string, unknown>;

/** The fields the form draws a control of its own for; every other field the
 *  vocabulary serves is drawn by its type. */
export const OWN_CONTROLS = ["id", "server", "tool", "arguments", "budget_seconds", "formats"];

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Whether `value` holds `key` itself, never through its prototype. */
export function owns(value: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

/** `map[key]` where the map holds the key itself; `undefined` otherwise, so a
 *  name such as `constructor` never reads an object's own machinery. */
export function ownEntry<T>(map: Record<string, T> | null | undefined, key: string): T | undefined {
  return map && Object.prototype.hasOwnProperty.call(map, key) ? map[key] : undefined;
}

/** The stored value as a list of steps, or `null` when it is not one (the
 *  editor then shows it as JSON). Nothing stored is no steps. */
export function readSteps(value: unknown): StepValue[] | null {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) return null;
  return value.every(isObject) ? (value as StepValue[]) : null;
}

/** The served field called `name`, if the API serves one. */
export function fieldOf(
  vocabulary: PackStepVocabulary,
  name: string,
): PackStepField | undefined {
  return vocabulary.fields.find((field) => field.name === name);
}

/** `step` with its known fields in the model's order, then the rest as stored.
 *  Built with `Object.fromEntries`, so any key, `__proto__` included, stays a
 *  key of the step. */
export function canonicalStep(step: StepValue, vocabulary: PackStepVocabulary): StepValue {
  const known = vocabulary.fields.map((field) => field.name).filter((name) => owns(step, name));
  const taken = new Set(known);
  const rest = Object.keys(step).filter((name) => !taken.has(name));
  return Object.fromEntries([...known, ...rest].map((name) => [name, step[name]]));
}

/** `step` with `name` set to `value`, or left unset where `value` is
 *  `undefined`, in the model's order. */
export function withField(
  step: StepValue,
  name: string,
  value: unknown,
  vocabulary: PackStepVocabulary,
): StepValue {
  const entries = Object.keys(step)
    .filter((key) => key !== name)
    .map((key): [string, unknown] => [key, step[key]]);
  if (value !== undefined) entries.push([name, value]);
  return canonicalStep(Object.fromEntries(entries), vocabulary);
}

/** The fields of `step` the vocabulary does not serve: shown, and kept. */
export function unknownFields(step: StepValue, vocabulary: PackStepVocabulary): string[] {
  const known = new Set(vocabulary.fields.map((field) => field.name));
  return Object.keys(step).filter((name) => !known.has(name));
}

/** What a value of each served JSON type is called where one is not. */
const TYPE_WORDS: Record<string, string> = {
  string: "text",
  number: "a number",
  integer: "a whole number",
  boolean: "true or false",
  array: "a list",
  object: "an object",
};

/** Whether `value` is of `field`'s served type; a field of no single type
 *  takes anything. */
export function fitsField(value: unknown, field: PackStepField): boolean {
  if (value === null) return field.nullable;
  switch (field.type) {
    case "string":
      return typeof value === "string";
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "boolean":
      return typeof value === "boolean";
    case "array":
      return (
        Array.isArray(value) &&
        (field.items !== "string" || value.every((item) => typeof item === "string"))
      );
    case "object":
      return isObject(value);
    default:
      return true;
  }
}

/** Each field `step` holds a value of another type than the one served, said
 *  in a line: the form cannot draw such a value in its control, so it says so. */
export function typeProblems(step: StepValue, vocabulary: PackStepVocabulary): string[] {
  return vocabulary.fields
    .filter((field) => owns(step, field.name) && !fitsField(step[field.name], field))
    .map((field) => {
      const wanted = TYPE_WORDS[field.type] ?? field.type;
      const listOf =
        field.type === "array" && field.items ? ` of ${TYPE_WORDS[field.items] ?? field.items}` : "";
      return `${field.name} holds ${JSON.stringify(step[field.name])}, not ${wanted}${listOf}; edit it as JSON`;
    });
}

/** `list` with the item at `from` moved to `to`. */
export function moveItem<T>(list: readonly T[], from: number, to: number): T[] {
  if (from === to || to < 0 || to >= list.length || from < 0 || from >= list.length) {
    return [...list];
  }
  const out = [...list];
  const [item] = out.splice(from, 1);
  out.splice(to, 0, item);
  return out;
}

/** `list` without the item at `index`. */
export function dropItem<T>(list: readonly T[], index: number): T[] {
  return list.filter((_, i) => i !== index);
}

/** `list` with the item at `index` replaced. */
export function replaceItem<T>(list: readonly T[], index: number, item: T): T[] {
  return list.map((held, i) => (i === index ? item : held));
}

/** The shipped steps by id, as they dump. */
export function shippedSteps(vocabulary: PackStepVocabulary): Map<string, StepValue> {
  const out = new Map<string, StepValue>();
  for (const step of vocabulary.shipped) {
    if (typeof step.id === "string") out.set(step.id, step);
  }
  return out;
}

/** A step's id as text; `""` for none. */
export function stepId(step: StepValue): string {
  return typeof step.id === "string" ? step.id : "";
}

function idRule(vocabulary: PackStepVocabulary): RegExp | null {
  try {
    return new RegExp(vocabulary.id_pattern);
  } catch {
    return null;
  }
}

/** What the save says about `id` on its own: nothing, or that it does not
 *  read as a whole step id. */
function idProblem(id: string, vocabulary: PackStepVocabulary): string | null {
  const rule = idRule(vocabulary);
  if (rule && !rule.test(id)) return `a step id matches ${vocabulary.id_pattern}`;
  return null;
}

/** Why `id` cannot name a new step beside `steps`, or `null` when it can. */
export function newStepError(
  id: string,
  steps: readonly StepValue[],
  vocabulary: PackStepVocabulary,
): string | null {
  const problem = idProblem(id, vocabulary);
  if (problem) return problem;
  if (steps.some((step) => stepId(step) === id)) return `step '${id}' is already declared`;
  return null;
}

/** Per position, what the save will say about a step's id: none, one that does
 *  not read as an id, or one declared twice. */
export function idProblems(
  steps: readonly StepValue[],
  vocabulary: PackStepVocabulary,
): Map<number, string> {
  const seen = new Set<string>();
  const out = new Map<number, string>();
  steps.forEach((step, index) => {
    const id = stepId(step);
    if (!id) {
      out.set(index, "a step names its id");
      return;
    }
    const problem = idProblem(id, vocabulary);
    if (problem) {
      out.set(index, problem);
      return;
    }
    if (seen.has(id)) out.set(index, `step '${id}' is declared twice`);
    seen.add(id);
  });
  return out;
}

/** A stable key per step for the list it is drawn in: its id, numbered where
 *  two steps share one. */
export function stepKeys(steps: readonly StepValue[]): string[] {
  const count = new Map<string, number>();
  return steps.map((step) => {
    const id = stepId(step);
    const n = (count.get(id) ?? 0) + 1;
    count.set(id, n);
    return `${id}#${n}`;
  });
}

/** How a declared step stands to the shipped list: a step of one's own, one
 *  that changes its shipped step field by field, or one that replaces it at
 *  its place and keeps only its id. */
export type Standing = "own" | "over" | "replaces";

/** A JSON value read as Python reads it in a condition: empty and zero are false. */
function truthy(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (typeof value === "string") return value !== "";
  if (typeof value === "number") return value !== 0;
  if (typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.length > 0;
  if (isObject(value)) return Object.keys(value).length > 0;
  return true;
}

/**
 * The step's standing, by the served rule the save lays a declaration over the
 * shipped list with: under a shipped id, a declaration that sets one of the
 * `replacing_fields` to a value other than the shipped step's (an empty value
 * only where the rule says it counts) replaces that step.
 */
export function standing(step: StepValue, vocabulary: PackStepVocabulary): Standing {
  const id = stepId(step);
  const compared = ownEntry(vocabulary.shipped_compared, id);
  if (compared === undefined || !shippedSteps(vocabulary).has(id)) return "own";
  for (const rule of vocabulary.replacing_fields) {
    if (!owns(step, rule.field)) continue;
    const value = step[rule.field];
    const against = ownEntry(compared, rule.compared_with);
    if ((truthy(value) || rule.empty_counts) && !deepEqual(value, against)) return "replaces";
  }
  return "over";
}

/** The value a field of `step` holds where the step does not set it: the
 *  shipped step's for a step that changes it, else the field's default. */
export function inheritedValue(
  step: StepValue,
  field: PackStepField,
  vocabulary: PackStepVocabulary,
): unknown {
  if (standing(step, vocabulary) === "over") {
    const shipped = shippedSteps(vocabulary).get(stepId(step));
    if (shipped && owns(shipped, field.name)) return shipped[field.name];
  }
  return field.default;
}

/** The value of a field the save puts in force for `step`. */
export function inForce(
  step: StepValue,
  field: PackStepField,
  vocabulary: PackStepVocabulary,
): unknown {
  return owns(step, field.name) ? step[field.name] : inheritedValue(step, field, vocabulary);
}

/** Whether the step runs: its `enabled` as the save puts it in force. The save
 *  checks the server and the tools list of a step that runs, and of no other. */
export function runs(step: StepValue, vocabulary: PackStepVocabulary): boolean {
  const field = fieldOf(vocabulary, "enabled");
  return field ? inForce(step, field, vocabulary) !== false : true;
}

/**
 * The note on a step named as one of the pack state's own keys that starts
 * beside the pack (`starts_after` in force): it runs as any other step, and how
 * it ran is recorded apart from that key. `""` for any other step: a step that
 * starts after none writes no such record.
 */
export function stateKeyNote(step: StepValue, vocabulary: PackStepVocabulary): string {
  const id = stepId(step);
  if (!vocabulary.state_keys.includes(id)) return "";
  const field = fieldOf(vocabulary, "starts_after");
  const after = field ? inForce(step, field, vocabulary) : step.starts_after;
  if (typeof after !== "string" || after === "") return "";
  return `'${id}' is also a key of the pack's own state: the step runs as any other, and how it ran beside the pack is recorded apart from that key, in the pack's facts and the run summary`;
}

/** A field's empty value (empty text, list or object, or `null` where the
 *  field takes it); `undefined` for a field that has none. */
export function emptyValue(field: PackStepField): unknown {
  if (field.type === "string") return "";
  if (field.type === "array") return [];
  if (field.type === "object") return {};
  if (field.nullable) return null;
  return undefined;
}

/** Whether `value` is empty text, an empty list or object, or `null`. */
export function isEmptyValue(value: unknown): boolean {
  if (value === "" || value === null) return true;
  if (Array.isArray(value)) return value.length === 0;
  return isObject(value) && Object.keys(value).length === 0;
}

/**
 * What emptying a field writes. Where the step would hold that same empty
 * value with the field unset (a step of one's own, one that replaces its
 * shipped step, a shipped value that is empty itself) the field is left unset,
 * as it would be written by hand. Elsewhere the empty value is written: it
 * stands in place of the shipped value, so emptying a box never brings the
 * shipped value back.
 */
export function clearedValue(
  step: StepValue,
  field: PackStepField,
  vocabulary: PackStepVocabulary,
): unknown {
  const empty = emptyValue(field);
  if (empty === undefined) return undefined;
  return deepEqual(empty, inheritedValue(step, field, vocabulary)) ? undefined : empty;
}

/** One placeholder a template names that the API's list does not hold. */
export interface UnknownPlaceholder {
  /** The top-level argument whose value holds it. */
  argument: string;
  placeholder: string;
}

/** The placeholder pattern as a global expression, or `null` when it does not
 *  read in this browser (the save still checks it). */
export function placeholderRule(vocabulary: PackStepVocabulary): RegExp | null {
  try {
    return new RegExp(vocabulary.placeholder_pattern, "g");
  } catch {
    return null;
  }
}

/**
 * Every placeholder `template` names at any depth that the vocabulary does not
 * list, in the order written, the same reading the save makes: each string of
 * the template, inside objects and lists too, is read for the served pattern,
 * and a match whose name is not served is refused there.
 *
 * Walked with a stack of its own, so a deep template costs its size and no
 * recursion; a match of no characters moves the reading on by one, so no
 * pattern can hold it in place.
 */
export function unknownPlaceholders(
  template: unknown,
  vocabulary: PackStepVocabulary,
): UnknownPlaceholder[] {
  const rule = placeholderRule(vocabulary);
  if (!rule || !isObject(template)) return [];
  const known = new Set(vocabulary.placeholders.map((term) => term.name));
  const found: UnknownPlaceholder[] = [];
  for (const argument of Object.keys(template)) {
    const stack: unknown[] = [template[argument]];
    while (stack.length > 0) {
      const held = stack.pop();
      if (typeof held === "string") {
        rule.lastIndex = 0;
        for (let match = rule.exec(held); match !== null; match = rule.exec(held)) {
          if (match[0] === "") rule.lastIndex += 1;
          const name = match[1] ?? "";
          if (!known.has(name)) found.push({ argument, placeholder: name });
        }
      } else if (Array.isArray(held)) {
        for (let i = held.length - 1; i >= 0; i -= 1) stack.push(held[i]);
      } else if (isObject(held)) {
        const values = Object.values(held);
        for (let i = values.length - 1; i >= 0; i -= 1) stack.push(values[i]);
      }
    }
  }
  return found;
}

/** The sentence a flagged placeholder is shown with. */
export function placeholderMessage(
  found: UnknownPlaceholder,
  vocabulary: PackStepVocabulary,
): string {
  const known = vocabulary.placeholders.map((term) => `{${term.name}}`).join(", ");
  return `argument '${found.argument}' names {${found.placeholder}}, which a template cannot name; known: ${known}`;
}

/** One argument of a template as a row: a name, and its value, a string the
 *  form edits or any other JSON value, which it shows and keeps. */
export interface ArgumentRow {
  name: string;
  value: unknown;
}

/** A template's arguments as rows, in their order. */
export function argumentRows(template: unknown): ArgumentRow[] {
  if (!isObject(template)) return [];
  return Object.keys(template).map((name) => ({ name, value: template[name] }));
}

/** The rows as a template, or why they cannot be one yet. */
export function readArgumentRows(
  rows: readonly ArgumentRow[],
): { value: Record<string, unknown> } | { error: string } {
  const seen = new Set<string>();
  for (const [index, row] of rows.entries()) {
    if (row.name === "") return { error: `argument ${index + 1} has no name` };
    if (seen.has(row.name)) return { error: `argument '${row.name}' is named twice` };
    seen.add(row.name);
  }
  return { value: Object.fromEntries(rows.map((row) => [row.name, row.value])) };
}

/** A text field of `step` as the save puts it in force, `""` for another type. */
function textInForce(step: StepValue, name: string, vocabulary: PackStepVocabulary): string {
  const field = fieldOf(vocabulary, name);
  const value = field ? inForce(step, field, vocabulary) : step[name];
  return typeof value === "string" ? value : "";
}

/** The shipped value the served rule compares a step's `field` with, for the
 *  shipped step under `id`, as text; `null` where no shipped step or rule has one. */
function shippedValue(vocabulary: PackStepVocabulary, id: string, field: string): string | null {
  const rule = vocabulary.replacing_fields.find((held) => held.field === field);
  const values = ownEntry(vocabulary.shipped_compared, id);
  const value = rule && values ? ownEntry(values, rule.compared_with) : undefined;
  return typeof value === "string" ? value : null;
}

/** The tool a step with no server under `id` may call: its shipped step's own,
 *  where that step is one of the platform's own; `""` where there is none. */
function ownCall(vocabulary: PackStepVocabulary, id: string): string {
  const call = shippedValue(vocabulary, id, "tool");
  return call && shippedValue(vocabulary, id, "server") === "" ? call : "";
}

/** The save's words for a tool outside a server's tools list. */
export function notAllowed(tool: string, server: string): string {
  return `'${tool}' is not allowed on server '${server}'`;
}

/** The save's words for a step with no server that is not one of the
 *  platform's own. */
export function namesNoServer(id: string): string {
  return `step '${id}' names no server, and is not one of the platform's own steps: name the server whose tool it is`;
}

/** The tools the form offers a step, each one the save accepts, and the ones
 *  it leaves out with the save's reason. */
export interface ToolOffer {
  offered: string[];
  refused: { name: string; reason: string }[];
}

/**
 * What the tool box offers `step`. With no server in force, only the tool its
 * shipped step calls, the one tool the save lets a step of the platform's own
 * call. With a server, its `tools` list, the tools it declares and what its
 * last listing reported, except a tool outside its `tools` list where it has
 * one: that is left out with the save's reason.
 */
export function offeredTools({
  step,
  servers,
  listed,
  vocabulary,
}: {
  step: StepValue;
  servers: Record<string, McpServerEntry>;
  listed: readonly string[] | null | undefined;
  vocabulary: PackStepVocabulary;
}): ToolOffer {
  const server = textInForce(step, "server", vocabulary);
  if (!server) {
    const own = ownCall(vocabulary, stepId(step));
    return { offered: own ? [own] : [], refused: [] };
  }
  const held = ownEntry(servers, server);
  const allowed = held && Array.isArray(held.tools) ? held.tools : null;
  const facts: unknown = held?.tool_facts;
  const declared = isObject(facts)
    ? Object.keys(facts).filter((name) => name !== "" && facts[name] !== null)
    : [];
  const candidates = [...new Set([...(allowed ?? []), ...declared, ...(listed ?? [])])];
  if (allowed === null) return { offered: candidates, refused: [] };
  const permitted = new Set(allowed);
  return {
    offered: candidates.filter((name) => permitted.has(name)),
    refused: candidates
      .filter((name) => !permitted.has(name))
      .map((name) => ({ name, reason: notAllowed(name, server) })),
  };
}

/** What the form says about the tool `step` calls: the save's refusal, a note
 *  that it was not seen, or nothing. */
export interface ToolNote {
  level: "error" | "note";
  text: string;
}

export function toolNote({
  step,
  servers,
  listed,
  vocabulary,
}: {
  step: StepValue;
  servers: Record<string, McpServerEntry>;
  listed: readonly string[] | null | undefined;
  vocabulary: PackStepVocabulary;
}): ToolNote | null {
  const id = stepId(step);
  const server = textInForce(step, "server", vocabulary);
  const tool = textInForce(step, "tool", vocabulary);
  if (!server) {
    const own = ownCall(vocabulary, id);
    return own && (tool || id) === own ? null : { level: "error", text: namesNoServer(id) };
  }
  if (!tool) {
    return { level: "error", text: `step '${id}' names a server and no tool to call on it` };
  }
  const held = ownEntry(servers, server);
  if (held && Array.isArray(held.tools) && !held.tools.includes(tool)) {
    return runs(step, vocabulary)
      ? { level: "error", text: notAllowed(tool, server) }
      : {
          level: "note",
          text: `${notAllowed(tool, server)}: the save refuses it once the step is enabled`,
        };
  }
  if (offeredTools({ step, servers, listed, vocabulary }).offered.includes(tool)) return null;
  return {
    level: "note",
    text:
      listed === null || listed === undefined
        ? `'${tool}' was not seen among ${server}'s declared tools; List tools asks the server for its manifest`
        : `'${tool}' was not seen among ${server}'s declared tools or in its manifest`,
  };
}

/** A value as one line of text: a string as it is, anything else as JSON. */
export function shownValue(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined) return "";
  return JSON.stringify(value);
}

/** A field's value as a person reads it: a list of names joined, else as
 *  `shownValue` writes it. */
export function readableValue(value: unknown): string {
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) {
    return value.join(", ");
  }
  return shownValue(value);
}

/** The servers whose listing no longer describes them: each listing keeps the
 *  server's settings it was asked under, and a server whose staged settings
 *  changed since (or that is gone) has its listing dropped. */
export function staleListings(
  listings: Record<string, { config: unknown }>,
  servers: Record<string, McpServerEntry>,
): string[] {
  return Object.keys(listings).filter(
    (key) => !deepEqual(listings[key].config, ownEntry(servers, key)),
  );
}

/** Whether a number meets the served bounds of its field, and if not, why. */
export function boundProblem(value: number, field: PackStepField): string {
  const { minimum, maximum, exclusiveMinimum, exclusiveMaximum } = field.bounds;
  if (exclusiveMinimum !== undefined && !(value > exclusiveMinimum)) {
    return `must be greater than ${exclusiveMinimum}`;
  }
  if (minimum !== undefined && value < minimum) return `must be at least ${minimum}`;
  if (exclusiveMaximum !== undefined && !(value < exclusiveMaximum)) {
    return `must be less than ${exclusiveMaximum}`;
  }
  if (maximum !== undefined && value > maximum) return `must be at most ${maximum}`;
  return "";
}

/** How a field's text box reads its text: `undefined` leaves the field unset. */
export type BoxRead = { value: unknown } | { error: string };

/** The reading of a typed number for a field of type `number` or `integer`;
 *  an empty box gives `cleared` (`clearedValue`). */
export function readNumber(text: string, field: PackStepField, cleared?: unknown): BoxRead {
  const trimmed = text.trim();
  if (trimmed === "") return { value: cleared };
  const value = Number(trimmed);
  if (!Number.isFinite(value)) return { error: "not a number yet" };
  if (field.type === "integer" && !Number.isInteger(value)) return { error: "a whole number" };
  return { value };
}

/** The reading of a typed list of names, split at commas and spaces; an empty
 *  box gives `cleared`. */
export function readNames(text: string, cleared?: unknown): BoxRead {
  const names = text
    .split(/[\s,]+/)
    .map((name) => name.trim())
    .filter(Boolean);
  return { value: names.length > 0 ? names : cleared };
}

/** The reading of a typed text; an empty box gives `cleared`. */
export function readText(text: string, cleared?: unknown): BoxRead {
  return { value: text === "" ? cleared : text };
}

/** The served errors about the steps beyond the leaf's own key, in order. */
export function nestedErrors(errors: Record<string, string>, key: string): [string, string][] {
  return Object.entries(errors).filter(([at]) => at.startsWith(`${key}.`));
}
