"use client";

import { useState } from "react";
import type { McpServerEntry, SampleOpenEntry } from "@/types/settings";
import {
  readEnvNames,
  readErrorPatterns,
  readMount,
  readRoles,
  readToolFacts,
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
 * list is not reformatted under the cursor, and what reaches the staged map is
 * always a value the reader accepted. The reader's message is shown under the
 * box until the text reads.
 */
function ReadField<T>({
  label,
  ariaLabel,
  initial,
  rows,
  mono,
  read,
  onValue,
}: {
  label: string;
  ariaLabel: string;
  initial: string;
  rows: number;
  mono?: boolean;
  read: (text: string) => Read<T>;
  onValue: (value: T) => void;
}) {
  const [text, setText] = useState(initial);
  const [error, setError] = useState<string | null>(null);

  const stage = (next: string) => {
    setText(next);
    const result = read(next);
    if (result.error !== null) {
      setError(result.error);
      return;
    }
    setError(null);
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

/**
 * The server's declaration: what the platform reads about the server and its
 * tools instead of a table of tool names. Closed by default, since a server
 * an operator adds works with none and a built-in ships its own; a field left
 * as the API showed it keeps following the shipped value.
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
  return (
    <details className="border border-border rounded p-2" data-declaration={serverKey}>
      <summary className="text-xs text-text-muted cursor-pointer">Declaration</summary>
      <p className="text-[11px] text-text-secondary mt-1">
        What the platform reads about this server and its tools. A built-in ships its own;
        a server you add needs none to work. See the configuration guide for every field.
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
          label="Sample mount (absolute path inside the server, or empty)"
          ariaLabel={`${serverKey} sample_mount`}
          initial={server.sample_mount ?? ""}
          rows={1}
          read={readMount}
          onValue={(sample_mount) => put({ sample_mount })}
        />
        <ReadField
          label="Roles (comma-separated words)"
          ariaLabel={`${serverKey} roles`}
          initial={(server.roles ?? []).join(", ")}
          rows={1}
          read={readRoles}
          onValue={(roles) => put({ roles })}
        />
        <ReadField
          label="Required environment names (one per line)"
          ariaLabel={`${serverKey} required_env_allow`}
          initial={(server.required_env_allow ?? []).join("\n")}
          rows={2}
          read={readEnvNames}
          onValue={(required_env_allow) => put({ required_env_allow })}
        />
        <label className="flex items-center gap-1 text-text-secondary self-end">
          <input
            type="checkbox"
            aria-label={`${serverKey} reads_staged_sample`}
            checked={server.reads_staged_sample ?? false}
            onChange={(e) => put({ reads_staged_sample: e.target.checked })}
          />
          its path-taking tools read the staged sample
        </label>
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
            label="Error patterns (JSON list of {match, code, remediation, tools})"
            ariaLabel={`${serverKey} error_patterns`}
            initial={showJson(server.error_patterns)}
            rows={3}
            mono
            read={readErrorPatterns}
            onValue={(error_patterns) => put({ error_patterns })}
          />
        </div>
        <div className="sm:col-span-2">
          <ReadField
            label="Tool declarations (JSON object keyed by tool name, each with a kind)"
            ariaLabel={`${serverKey} tool_facts`}
            initial={showJson(server.tool_facts)}
            rows={6}
            mono
            read={readToolFacts}
            onValue={(tool_facts) => put({ tool_facts })}
          />
        </div>
      </div>
    </details>
  );
}
