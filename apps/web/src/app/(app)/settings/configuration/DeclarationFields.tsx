"use client";

import { useEffect, useRef, useState } from "react";
import { shippedServerToolFacts } from "@/lib/providerFacts";
import type {
  McpServerEntry,
  PrepassToolsEntry,
  SampleOpenEntry,
  ToolDeclarationFields,
  ToolFactsEntry,
} from "@/types/settings";
import { deepEqual } from "./mapEditorHelpers";
import { useOptionalSettingsContext } from "./SettingsContext";
import {
  DECLARATION_PANEL_COPY,
  readCallTimeout,
  readCredentialBootstrap,
  readEnvNames,
  readErrorPatterns,
  readLauncherDepth,
  readMount,
  readPrefixes,
  readReferenceUrls,
  readRoles,
  readToolFacts,
  readWorkDir,
  showJson,
  usableFields,
  withPrepass,
  type Read,
} from "./declarationFields";
import {
  asChanges,
  CHANGES_MARK,
  changedTools,
  mergeToolFacts,
  namesAnyTool,
  resetTool,
  toolFactsChanges,
  type ToolChange,
  type ToolFactsChanges,
} from "./toolFactsChanges";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

const EMPTY_OPEN: SampleOpenEntry = {
  open_tool: "",
  path_argument: "",
  name_field: "",
  select_tool: "",
  select_argument: "",
  analyse_tool: "",
  analyse_argument: "",
};

/* The seven fields of `sample_open`, in the order the configuration guide
 * lists them, with the guide's words. */
const OPEN_FIELDS: { key: keyof SampleOpenEntry; label: string; hint: string }[] = [
  { key: "open_tool", label: "Open tool", hint: "the tool that opens a sample; empty declares nothing" },
  { key: "path_argument", label: "Open tool's path argument", hint: "the argument the path goes in" },
  { key: "name_field", label: "Opened name field", hint: "the answer's field naming what was opened; empty means the path" },
  { key: "select_tool", label: "Select tool", hint: "selects a sample already open; empty answers from the note" },
  { key: "select_argument", label: "Select tool's argument", hint: "the argument the opened name goes in" },
  { key: "analyse_tool", label: "Analysis tool", hint: "runs the server's analysis after the first open; empty runs none" },
  { key: "analyse_argument", label: "Analysis tool's argument", hint: "the argument the opened name goes in; empty calls it with none" },
];

const EMPTY_PREPASS: PrepassToolsEntry = { call_graph: "", function_hashes: "", anti_analysis: "" };

/* The three fields of `prepass_tools`, with the guide's words. */
const PREPASS_FIELDS: { key: keyof PrepassToolsEntry; label: string; hint: string }[] = [
  { key: "call_graph", label: "Call-graph tool", hint: "the program's whole call graph, for the priority-functions pre-pass" },
  { key: "function_hashes", label: "Function-hash tool", hint: "a hash per function, for function-hash attribution" },
  { key: "anti_analysis", label: "Anti-analysis scan tool", hint: "the triage pack's anti-analysis scan" },
];

/**
 * A text box whose value is staged only once it reads as one.
 *
 * The typed text is local state, as in the environment fields: a half-typed
 * list is not reformatted under the cursor. While the text does not read, the
 * box says why and tells the console, which holds Apply: the staged map still
 * holds the last value that read, which is not what the box shows. When the
 * staged value changes from outside the box (a discard, a reload), the box
 * shows it again.
 */
function ReadField<T>({
  id,
  label,
  ariaLabel,
  value,
  show,
  rows,
  mono,
  read,
  onValue,
}: {
  id: string;
  label: string;
  ariaLabel: string;
  value: T;
  show: (value: T) => string;
  rows: number;
  mono?: boolean;
  read: (text: string) => Read<T>;
  onValue: (value: T) => void;
}) {
  const ctx = useOptionalSettingsContext();
  const note = ctx?.noteUnreadInput;
  const [text, setText] = useState(() => show(value));
  const [error, setError] = useState<string | null>(null);
  const staged = useRef<T>(value);

  useEffect(() => {
    if (!deepEqual(value, staged.current)) {
      staged.current = value;
      setText(show(value));
      setError(null);
      note?.(id, null);
    }
    // `show` and `note` are stable for a box; only an outside change of the
    // value decides whether the text is shown afresh.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  // A discard or reset elsewhere: text that never read is dropped and the
  // staged value shown again, which also lifts its hold on Apply.
  const generation = ctx?.discardGeneration ?? 0;
  const [seenGeneration, setSeenGeneration] = useState(generation);
  if (generation !== seenGeneration) {
    setSeenGeneration(generation);
    if (error !== null) {
      setText(show(value));
      setError(null);
    }
  }
  useEffect(() => {
    if (error === null) note?.(id, null);
    // Only a new discard decides this; the box's own edits do not.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [generation]);

  useEffect(() => () => note?.(id, null), [id, note]);

  const stage = (next: string) => {
    setText(next);
    const result = read(next);
    if (result.error !== null) {
      setError(result.error);
      note?.(id, `${label}: ${result.error}`);
      return;
    }
    setError(null);
    note?.(id, null);
    staged.current = result.value;
    onValue(result.value);
  };

  const Box = rows > 1 ? "textarea" : "input";
  return (
    <label className="block">
      <span className="text-text-muted">{label}</span>
      <Box
        className={`${input}${mono ? " font-mono" : ""}`}
        rows={rows > 1 ? rows : undefined}
        aria-label={ariaLabel}
        aria-invalid={error ? true : undefined}
        value={text}
        onChange={(e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
          stage(e.target.value)
        }
      />
      {error && (
        <div className="text-[11px] text-status-red mt-1" role="alert">
          {error}
        </div>
      )}
    </label>
  );
}

/** A tool's name as the console shows it: an empty one as `""`, so it is seen. */
function shownToolName(tool: string): string {
  return tool === "" ? '""' : tool;
}

/** The word on a tool's reset button. A tool the block does not ship is the
 *  operator's own and is removed; one whose stored change conflicts with this
 *  release is reset (its stored change removed), shipped or not. */
function resetWord(state: ToolChange["state"], conflicting: boolean): string {
  if (state !== "added") return "Reset to shipped";
  return conflicting ? "Reset" : "Remove";
}

const CHANGE_LABEL: Record<ToolChange["state"], string> = {
  changed: "changed",
  removed: "removed",
  added: "yours, not shipped",
};

/**
 * A block's tool declarations, edited as they are in force.
 *
 * What is stored (`changes`) is the block's changes over what it ships, one
 * tool at a time; the box shows the shipped declarations with those changes
 * over them, and stages what the edited text changes of the shipped ones. A
 * tool left as shipped is not staged, so it keeps following later releases.
 * Below the box, each tool that carries a change is listed with a reset to
 * what ships. With nothing shipped (a server an operator added) the box is
 * the whole map and nothing is listed.
 *
 * While the typed text stands for the changes staged, the box keeps showing
 * it as typed rather than re-rendering it filled from the shipped values.
 *
 * A tool named in `conflicts` carries a stored change the API leaves out
 * because it does not validate over what this release ships (the tool is in
 * force as shipped); it is marked so the operator resets or edits it.
 */
export function ToolFactsBox({
  id,
  ariaLabel,
  serverKey,
  shipped,
  changes,
  fields,
  conflicts = [],
  onChanges,
}: {
  id: string;
  ariaLabel: string;
  serverKey: string;
  shipped: Record<string, Record<string, unknown>>;
  changes: ToolFactsChanges | undefined;
  fields: ToolDeclarationFields | null;
  conflicts?: readonly string[];
  onChanges: (changes: ToolFactsChanges) => void;
}) {
  const [held, setHeld] = useState<{
    changes: ToolFactsChanges;
    inForce: Record<string, ToolFactsEntry>;
  } | null>(null);
  // Read as the API reads it: a map without the mark is the whole map.
  const read = asChanges(shipped, changes, fields);
  const inForce =
    held !== null && deepEqual(held.changes, changes ?? {})
      ? held.inForce
      : mergeToolFacts(shipped, read);
  const ships = Object.keys(shipped).length > 0;
  const changed = ships ? changedTools(shipped, read) : [];
  // A conflicting name no row below carries (the mark's key stands for the
  // stored map as a whole) is said on its own line, never dropped.
  const listed = new Set(changed.map(({ tool }) => tool));
  const unlisted = conflicts.filter((tool) => !listed.has(tool));
  return (
    <>
      <ReadField
        id={id}
        label={
          ships
            ? "Tool declarations in force (JSON object keyed by tool name; a tool left as shipped keeps following later releases)"
            : "Tool declarations (JSON object keyed by tool name, each with its facts; a kind is optional)"
        }
        ariaLabel={ariaLabel}
        value={inForce}
        show={showJson}
        rows={6}
        mono
        read={(text) => readToolFacts(text, serverKey, fields)}
        onValue={(next) => {
          const staged = toolFactsChanges(next, shipped, fields);
          setHeld({ changes: staged, inForce: next });
          onChanges(staged);
        }}
      />
      {unlisted.length > 0 && (
        <p className="mt-1 text-[11px] text-status-orange" data-tool-conflicts-unlisted={serverKey}>
          {unlisted.includes(CHANGES_MARK)
            ? "The stored tool declarations of this block have a form no release writes, so " +
              "they are not in force and what ships is; saving the block writes them anew."
            : `Stored changes not in force: ${unlisted.map(shownToolName).join(", ")}`}
        </p>
      )}
      {ships && (
        <div className="mt-1 text-[11px] text-text-secondary" data-tool-changes={serverKey}>
          {changed.length === 0 ? (
            <p>Every tool is as shipped.</p>
          ) : (
            <>
              <p>Tools carrying your changes:</p>
              <ul className="mt-1 space-y-0.5">
                {changed.map(({ tool, state }) => (
                  <li key={tool} className="flex items-center gap-2" data-tool-change={state}>
                    <span className="font-mono text-text-primary">{tool}</span>
                    <span className="text-text-muted">{CHANGE_LABEL[state]}</span>
                    {conflicts.includes(tool) && (
                      <span className="text-status-orange" data-tool-conflict={tool}>
                        conflicts with this release&apos;s declaration: your change is not in
                        force until you reset or edit it
                      </span>
                    )}
                    <button
                      type="button"
                      className="text-accent-strong"
                      aria-label={`reset ${tool} to shipped`}
                      onClick={() => {
                        setHeld(null);
                        onChanges(resetTool(read, tool));
                      }}
                    >
                      {resetWord(state, conflicts.includes(tool))}
                    </button>
                  </li>
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </>
  );
}

const joinComma = (v: string[]) => v.join(", ");
const joinLines = (v: string[]) => v.join("\n");
const asIs = (v: string) => v;
const showSeconds = (v: number | null) => (v === null ? "" : String(v));
const showDepth = (v: number | null) => (v === null ? "" : String(v));

/**
 * The server's declaration: the facts the platform will read about this
 * server and its tools instead of a table of tool names. Closed by default,
 * since a server an operator adds works with none and a built-in ships its
 * own; a field left as the API showed it keeps following the shipped value.
 */
export default function DeclarationFields({
  serverKey,
  server,
  put,
}: {
  serverKey: string;
  server: McpServerEntry;
  put: (next: Partial<McpServerEntry>) => void;
}) {
  const schema = useOptionalSettingsContext()?.schema;
  const fields = usableFields(schema?.tool_declaration_fields);
  const shipped = shippedServerToolFacts(schema, serverKey);
  const open = server.sample_open ?? EMPTY_OPEN;
  const prepass = server.prepass_tools ?? EMPTY_PREPASS;
  const box = (field: string) => `${serverKey}.${field}`;
  return (
    <details className="border border-border rounded p-2" data-declaration={serverKey}>
      <summary className="text-xs text-text-muted cursor-pointer">Declaration</summary>
      <p className="text-[11px] text-text-secondary mt-1">
        {DECLARATION_PANEL_COPY}
      </p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs mt-2">
        <fieldset className="sm:col-span-2 border border-border rounded p-2">
          <legend className="text-xs text-text-muted px-1">Opening the sample</legend>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {OPEN_FIELDS.map(({ key, label, hint }) => (
              <label key={key} className="block">
                <span className="text-text-muted">{label}</span>
                <input
                  className={input}
                  aria-label={`${serverKey} sample_open ${key}`}
                  placeholder={hint}
                  value={open[key]}
                  onChange={(e) => put({ sample_open: { ...open, [key]: e.target.value } })}
                />
              </label>
            ))}
          </div>
        </fieldset>
        <fieldset className="sm:col-span-2 border border-border rounded p-2">
          <legend className="text-xs text-text-muted px-1">
            Tools the platform calls (when the generic static provider drives this server)
          </legend>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            {PREPASS_FIELDS.map(({ key, label, hint }) => (
              <label key={key} className="block">
                <span className="text-text-muted">{label}</span>
                <input
                  className={input}
                  aria-label={`${serverKey} prepass_tools ${key}`}
                  placeholder={hint}
                  value={prepass[key]}
                  onChange={(e) => put({ prepass_tools: withPrepass(prepass, key, e.target.value) })}
                />
              </label>
            ))}
          </div>
        </fieldset>
        <ReadField
          id={box("sample_mount")}
          label="Sample mount (absolute path inside the server, or empty)"
          ariaLabel={`${serverKey} sample_mount`}
          value={server.sample_mount ?? ""}
          show={asIs}
          rows={1}
          read={readMount}
          onValue={(sample_mount) => put({ sample_mount })}
        />
        <ReadField
          id={box("work_dir")}
          label="Work directory (one name under the samples directory, or empty)"
          ariaLabel={`${serverKey} work_dir`}
          value={server.work_dir ?? ""}
          show={asIs}
          rows={1}
          read={readWorkDir}
          onValue={(work_dir) => put({ work_dir })}
        />
        <ReadField
          id={box("roles")}
          label="Roles (comma-separated words)"
          ariaLabel={`${serverKey} roles`}
          value={server.roles ?? []}
          show={joinComma}
          rows={1}
          read={readRoles}
          onValue={(roles) => put({ roles })}
        />
        <ReadField
          id={box("auto_name_prefixes")}
          label="Auto-name prefixes (comma-separated, such as FUN_ or fcn.)"
          ariaLabel={`${serverKey} auto_name_prefixes`}
          value={server.auto_name_prefixes ?? []}
          show={joinComma}
          rows={1}
          read={readPrefixes}
          onValue={(auto_name_prefixes) => put({ auto_name_prefixes })}
        />
        <ReadField
          id={box("required_env_allow")}
          label="Required environment names (one per line)"
          ariaLabel={`${serverKey} required_env_allow`}
          value={server.required_env_allow ?? []}
          show={joinLines}
          rows={2}
          read={readEnvNames}
          onValue={(required_env_allow) => put({ required_env_allow })}
        />
        <ReadField
          id={box("variable_names")}
          label="Non-secret variable names (one per line)"
          ariaLabel={`${serverKey} variable_names`}
          value={server.variable_names ?? []}
          show={joinLines}
          rows={2}
          read={readEnvNames}
          onValue={(variable_names) => put({ variable_names })}
        />
        <label className="flex items-center gap-1 text-text-secondary">
          <input
            type="checkbox"
            aria-label={`${serverKey} reads_staged_sample`}
            checked={server.reads_staged_sample ?? false}
            onChange={(e) => put({ reads_staged_sample: e.target.checked })}
          />
          its path-taking tools read the staged sample
        </label>
        <label className="flex items-center gap-1 text-text-secondary">
          <input
            type="checkbox"
            aria-label={`${serverKey} platform_owned`}
            checked={server.platform_owned ?? false}
            onChange={(e) => put({ platform_owned: e.target.checked })}
          />
          the platform&apos;s own server
        </label>
        <ReadField
          id={box("launcher_depth")}
          label="Launcher levels (top levels of the started process tree that are a launcher, not a reader; empty: none)"
          ariaLabel={`${serverKey} launcher_depth`}
          value={server.launcher_depth ?? null}
          show={showDepth}
          rows={1}
          read={readLauncherDepth}
          onValue={(launcher_depth) => put({ launcher_depth })}
        />
        <ReadField
          id={box("call_timeout_seconds")}
          label="Call timeout in seconds (from 0; 0: no deadline of its own; empty: the deployment's floor)"
          ariaLabel={`${serverKey} call_timeout_seconds`}
          value={server.call_timeout_seconds ?? null}
          show={showSeconds}
          rows={1}
          read={readCallTimeout}
          onValue={(call_timeout_seconds) => put({ call_timeout_seconds })}
        />
        <div className="sm:col-span-2">
          <ReadField
            id={box("reference_urls")}
            label="Reference URLs (one per line, naming {sha256}, {md5} or {sha1})"
            ariaLabel={`${serverKey} reference_urls`}
            value={server.reference_urls ?? []}
            show={joinLines}
            rows={2}
            read={readReferenceUrls}
            onValue={(reference_urls) => put({ reference_urls })}
          />
        </div>
        <label className="block sm:col-span-2">
          <span className="text-text-muted">Workflow text (shown only while this server is attached)</span>
          <textarea
            className={input}
            rows={3}
            aria-label={`${serverKey} prompt_fragment`}
            value={server.prompt_fragment ?? ""}
            onChange={(e) => put({ prompt_fragment: e.target.value })}
          />
        </label>
        <div className="sm:col-span-2">
          <ReadField
            id={box("error_patterns")}
            label="Error patterns (JSON list of {match, code, remediation, tools, …})"
            ariaLabel={`${serverKey} error_patterns`}
            value={server.error_patterns ?? []}
            show={showJson}
            rows={3}
            mono
            read={readErrorPatterns}
            onValue={(error_patterns) => put({ error_patterns })}
          />
        </div>
        <div className="sm:col-span-2">
          <ToolFactsBox
            id={box("tool_facts")}
            ariaLabel={`${serverKey} tool_facts`}
            serverKey={serverKey}
            shipped={shipped}
            changes={server.tool_facts}
            fields={fields}
            conflicts={schema?.tool_facts_conflicts?.[`mcp.servers.${serverKey}`]}
            onChanges={(tool_facts) => {
              // Nothing changed of what ships, where nothing was stored:
              // leave the entry as it was rather than stage an empty map.
              if (!namesAnyTool(tool_facts) && server.tool_facts === undefined) return;
              put({ tool_facts: tool_facts as McpServerEntry["tool_facts"] });
            }}
          />
        </div>
        <div className="sm:col-span-2">
          <ReadField
            id={box("credential_bootstrap")}
            label="Credential bootstrap (JSON object: url, body, token_json_path, token_prefix, family, facts, note)"
            ariaLabel={`${serverKey} credential_bootstrap`}
            value={server.credential_bootstrap ?? null}
            show={showJson}
            rows={4}
            mono
            read={readCredentialBootstrap}
            onValue={(credential_bootstrap) => put({ credential_bootstrap })}
          />
        </div>
      </div>
    </details>
  );
}
