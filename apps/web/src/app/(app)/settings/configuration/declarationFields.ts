/**
 * The server editor's Declaration section: reading what an operator typed.
 *
 * A server's declaration (`maljan.core.tool_declarations`) is the facts the
 * platform reads about the server and its tools instead of a table of tool
 * names. The API validates every field and answers with one message per bad
 * field, which the editor shows on the server; these readers only turn the
 * typed text into the value to stage, and say what is wrong with text that is
 * not yet a value, so a half-typed object is never staged.
 *
 * The vocabulary (a role, a kind) is open: any lowercase word is accepted
 * here, as by the API. Nothing in this file names a tool or a server.
 */

import type {
  CredentialBootstrapEntry,
  ErrorPatternEntry,
  ToolDeclarationFields,
  ToolFactsEntry,
} from "@/types/settings";

/** A vocabulary word, as the API checks one: lowercase, a letter first. */
export const WORD = /^[a-z][a-z0-9_]{0,63}$/;
/** An environment variable name. */
export const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

export type Read<T> = { value: T; error: null } | { value: null; error: string };

function ok<T>(value: T): Read<T> {
  return { value, error: null };
}

function bad<T>(error: string): Read<T> {
  return { value: null, error };
}

/** Words typed one per line or comma-separated; empty entries dropped. */
export function splitWords(text: string): string[] {
  return text
    .split(/[\n,]/)
    .map((w) => w.trim())
    .filter((w) => w !== "");
}

/** Roles: lowercase words. */
export function readRoles(text: string): Read<string[]> {
  const words = splitWords(text);
  const wrong = words.filter((w) => !WORD.test(w));
  if (wrong.length > 0) {
    return bad(
      `not a role word: ${wrong.join(", ")} (lowercase letters, digits and underscores, a letter first)`
    );
  }
  return ok(words);
}

/** Required environment names: one per line. */
export function readEnvNames(text: string): Read<string[]> {
  const names = splitWords(text);
  const wrong = names.filter((n) => !ENV_NAME.test(n));
  if (wrong.length > 0) return bad(`not an environment variable name: ${wrong.join(", ")}`);
  return ok(names);
}

/** The mount: an absolute path inside the server, or empty. */
export function readMount(text: string): Read<string> {
  const value = text.trim();
  if (value !== "" && !value.startsWith("/")) {
    return bad("an absolute path inside the server (starting with /), or empty");
  }
  return ok(value);
}

/** The work directory: one directory name, or empty. */
export function readWorkDir(text: string): Read<string> {
  const value = text.trim();
  if (value === "." || value === ".." || value.includes("/") || value.includes("\\")) {
    return bad("one directory name under the samples directory, not a path");
  }
  return ok(value);
}

/** Auto-name prefixes: letters and digits ending in `_` or `.` (FUN_, fcn.). */
export function readPrefixes(text: string): Read<string[]> {
  const prefixes = splitWords(text);
  const wrong = prefixes.filter((p) => !/^[A-Za-z][A-Za-z0-9]*[_.]$/.test(p));
  if (wrong.length > 0) {
    return bad(`not a prefix: ${wrong.join(", ")} (letters and digits ending in _ or .)`);
  }
  return ok(prefixes);
}

/** Reference URL templates, one per line: https, naming {sha256}, {md5} or {sha1}. */
export function readReferenceUrls(text: string): Read<string[]> {
  const urls = text
    .split("\n")
    .map((u) => u.trim())
    .filter((u) => u !== "");
  for (const url of urls) {
    if (!url.startsWith("https://")) return bad(`${url}: a reference URL starts with https://`);
    if (!["{sha256}", "{md5}", "{sha1}"].some((p) => url.includes(p))) {
      return bad(`${url}: name {sha256}, {md5} or {sha1}`);
    }
  }
  return ok(urls);
}

function parseJson(text: string): Read<unknown> {
  if (text.trim() === "") return ok(undefined);
  try {
    return ok(JSON.parse(text) as unknown);
  } catch (err) {
    return bad(`not valid JSON: ${(err as Error).message}`);
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** Error patterns: a JSON list of `{match, code?, remediation?, tools?}`; empty is `[]`. */
export function readErrorPatterns(text: string): Read<ErrorPatternEntry[]> {
  const parsed = parseJson(text);
  if (parsed.error !== null) return bad(parsed.error);
  if (parsed.value === undefined) return ok([]);
  if (!Array.isArray(parsed.value)) return bad("expected a list of {match, code, remediation, tools}");
  for (const [i, item] of parsed.value.entries()) {
    if (!isObject(item) || typeof item.match !== "string" || item.match === "") {
      return bad(`pattern ${i + 1} needs a match: a regular expression held against the whole answer`);
    }
    if (item.code !== undefined && (typeof item.code !== "string" || !WORD.test(item.code))) {
      return bad(`pattern ${i + 1}: code is a lowercase word such as tool_failed or bad_argument`);
    }
  }
  return ok(parsed.value as ErrorPatternEntry[]);
}

/* Whether two JSON values are the same, keys in any order: how the API
 * compares a field with its default (`tool_declarations._same`). */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (isObject(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  return JSON.stringify(value === undefined ? null : value);
}

function sameJson(left: unknown, right: unknown): boolean {
  return canonical(left) === canonical(right);
}

/* The fields `facts` sets among `defaults`: present, and not at the default. */
function setAmong(facts: Record<string, unknown>, defaults: Record<string, unknown>): string[] {
  return Object.keys(defaults).filter(
    (key) => Object.prototype.hasOwnProperty.call(facts, key) && !sameJson(facts[key], defaults[key])
  );
}

/** Whether the no-kind word in `facts` names no kind: only when no
 *  kind-dependent field is set, as the API's `reads_no_kind` rules. */
export function readsNoKind(facts: Record<string, unknown>, fields: ToolDeclarationFields): boolean {
  return facts.kind === fields.no_kind && setAmong(facts, fields.kind_dependent).length === 0;
}

/** Tool declarations: a JSON object keyed by tool name, each with its facts; empty is `{}`.
 *  A name may hold `__`; only one spelled as this server's renamed tool
 *  (`<serverKey>__…`) is refused.
 *
 *  `fields` is the split the API serves with the settings schema
 *  (`tool_declaration_fields`): the field rules are applied from it, exactly
 *  as the API applies them to an edit -- no unknown field; the no-kind word
 *  names no kind only when no kind-dependent field is set; a declaration of
 *  no kind sets at least one field and no kind-dependent one, a field
 *  counting as set only when it differs from its default. Without it the box
 *  checks the shape alone and the API answers the rest on save. */
export function readToolFacts(
  text: string,
  serverKey = "",
  fields: ToolDeclarationFields | null = null
): Read<Record<string, ToolFactsEntry>> {
  const parsed = parseJson(text);
  if (parsed.error !== null) return bad(parsed.error);
  if (parsed.value === undefined) return ok({});
  if (!isObject(parsed.value)) return bad("expected an object keyed by tool name");
  for (const [tool, facts] of Object.entries(parsed.value)) {
    if (tool.trim() === "" || tool !== tool.trim()) {
      return bad(`${JSON.stringify(tool)}: a tool's own name, not empty or padded`);
    }
    if (serverKey && tool.startsWith(`${serverKey}__`)) {
      return bad(`${tool}: spelled as this server's renamed tool; use the tool's own name`);
    }
    if (!isObject(facts)) return bad(`${tool}: expected an object of the tool's facts`);
    const kind = fields !== null && readsNoKind(facts, fields) ? "" : facts.kind;
    const noKind = kind === undefined || kind === "";
    if (!noKind && (typeof kind !== "string" || !WORD.test(kind))) {
      return bad(`${tool}: kind is a lowercase word such as strings, rule_match or decompile`);
    }
    if (fields === null) continue;
    const known = new Set(["kind", ...Object.keys(fields.kind_free), ...Object.keys(fields.kind_dependent)]);
    const unknown = Object.keys(facts).filter((key) => !known.has(key));
    if (unknown.length) return bad(`${tool}: unknown field ${unknown.join(", ")}`);
    if (noKind) {
      // No kind states only the fields read without one.
      const needing = setAmong(facts, fields.kind_dependent);
      if (setAmong(facts, fields.kind_free).length === 0 && needing.length === 0) {
        return bad(
          `${tool}: name its kind or at least one of ${Object.keys(fields.kind_free).join(", ")}`
        );
      }
      if (needing.length) {
        return bad(`${tool}: ${needing.join(", ")} are read only through a kind; declare the kind`);
      }
    }
  }
  return ok(parsed.value as Record<string, ToolFactsEntry>);
}

/** How the server's credential is obtained: a JSON object with an https `url`
 *  and a `token_json_path`; empty declares none (`null`). The API checks the
 *  rest of it on save. */
export function readCredentialBootstrap(text: string): Read<CredentialBootstrapEntry | null> {
  const parsed = parseJson(text);
  if (parsed.error !== null) return bad(parsed.error);
  if (parsed.value === undefined) return ok(null);
  if (!isObject(parsed.value)) return bad("expected an object with url and token_json_path");
  const { url, token_json_path: path } = parsed.value;
  if (typeof url !== "string" || !url.startsWith("https://")) {
    return bad("url is the https address the request is sent to");
  }
  if (typeof path !== "string" || !path.startsWith("/")) {
    return bad("token_json_path is the path of the token in the answer, starting with '/'");
  }
  return ok(parsed.value as unknown as CredentialBootstrapEntry);
}

/** A JSON value as the box shows it: pretty, or empty for nothing declared. */
export function showJson(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (Array.isArray(value) && value.length === 0) return "";
  if (isObject(value) && Object.keys(value).length === 0) return "";
  return JSON.stringify(value, null, 2);
}
