"use client";

import { useEffect, useRef, useState } from "react";
import type { McpServerEntry, SampleOpenEntry } from "@/types/settings";
import { deepEqual } from "./mapEditorHelpers";
import { useOptionalSettingsContext } from "./SettingsContext";
import {
  readEnvNames,
  readErrorPatterns,
  readMount,
  readPrefixes,
  readReferenceUrls,
  readRoles,
  readToolFacts,
  readWorkDir,
  showJson,
  type Read,
} from "./declarationFields";

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

const joinComma = (v: string[]) => v.join(", ");
const joinLines = (v: string[]) => v.join("\n");
const asIs = (v: string) => v;

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
  const open = server.sample_open ?? EMPTY_OPEN;
  const box = (field: string) => `${serverKey}.${field}`;
  return (
    <details className="border border-border rounded p-2" data-declaration={serverKey}>
      <summary className="text-xs text-text-muted cursor-pointer">Declaration</summary>
      <p className="text-[11px] text-text-secondary mt-1">
        What the platform reads about this server and its tools. A built-in ships its own; a
        server you add needs none to work. Nothing reads the declaration yet besides
        sample_open. See the configuration guide for every field.
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
          <ReadField
            id={box("tool_facts")}
            label="Tool declarations (JSON object keyed by tool name, each with a kind)"
            ariaLabel={`${serverKey} tool_facts`}
            value={server.tool_facts ?? {}}
            show={showJson}
            rows={6}
            mono
            read={(text) => readToolFacts(text, serverKey)}
            onValue={(tool_facts) => put({ tool_facts })}
          />
        </div>
      </div>
    </details>
  );
}
