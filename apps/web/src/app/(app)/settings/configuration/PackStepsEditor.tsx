"use client";

/* The triage pack's steps as a form: one card per step, laid over the shipped
 * list, with the raw JSON kept as an advanced view of the same value.
 *
 * Everything the form offers or checks comes from the steps' catalog entry
 * (`pack_step_vocabulary`) and the tool servers in force; the rules live in
 * `packSteps.ts`, and the save stays the one judge of the list. What a card
 * shows as in force is what the save applies to the step. */

import { useEffect, useId, useRef, useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import { probeDetail } from "@/lib/probeDetail";
import type {
  CatalogEntry,
  McpServerEntry,
  PackStepField,
  PackStepVocabulary,
  ProbeResult,
  SettingValue,
} from "@/types/settings";
import { choiceRows, toggleChoice } from "./choiceRows";
import { deepEqual } from "./deepEqual";
import {
  OWN_CONTROLS,
  argumentRows,
  boundProblem,
  clearedValue,
  dropItem,
  emptyValue,
  fieldOf,
  fitsField,
  idProblems,
  inheritedValue,
  isEmptyValue,
  moveItem,
  nestedErrors,
  newStepError,
  offeredTools,
  ownEntry,
  owns,
  placeholderMessage,
  placeholderRule,
  readArgumentRows,
  readNames,
  readNumber,
  readSteps,
  readText,
  readableValue,
  replaceItem,
  runs,
  shippedSteps,
  shownValue,
  staleListings,
  standing,
  stateKeyNote,
  stepId,
  stepKeys,
  toolNote,
  typeProblems,
  unknownFields,
  unknownPlaceholders,
  withField,
  type ArgumentRow,
  type BoxRead,
  type Standing,
  type StepValue,
} from "./packSteps";
import { leftOutSteps } from "./packStepsLeftOut";
import { useOptionalSettingsContext } from "./SettingsContext";
import { capabilityCells, unavailableReason } from "./toolTableRows";

const BOX =
  "min-w-0 bg-bg-deep border border-border rounded px-2 py-1 text-xs text-text-primary focus:outline-none focus:border-accent";
const INPUT = `w-full ${BOX}`;
const BUTTON =
  "h-6 rounded border border-border px-2 text-[11px] text-text-secondary hover:text-text-primary hover:border-text-muted disabled:opacity-50 disabled:cursor-not-allowed";

type Probe = ProbeResult | "running";

/** The renderer box's two choices that are no renderer: leave the field unset,
 *  or set it empty. Neither can be a renderer's name. */
const RENDERER_UNSET = "(unset)";
const RENDERER_EMPTY = "(empty)";

/** What a field holds unset, as the placeholder of its box. */
function unsetSays(inherited: unknown, where: Standing): string {
  if (isEmptyValue(inherited) || inherited === undefined) return "unset";
  return `${where === "over" ? "shipped" : "default"}: ${readableValue(inherited)}`;
}

/** A box whose text is staged only once it reads, as the declaration fields'
 *  boxes are: while it does not, it says why and holds Apply. An outside
 *  change of the value (a discard, the JSON view) shows the value again. */
function TextBox({
  title,
  label,
  value,
  show,
  read,
  placeholder,
  flag,
  mono,
  onValue,
}: {
  title: string;
  label: string;
  value: unknown;
  show: (value: unknown) => string;
  read: (text: string) => BoxRead;
  placeholder?: string;
  flag?: string;
  mono?: boolean;
  onValue: (value: unknown) => void;
}) {
  const ctx = useOptionalSettingsContext();
  const note = ctx?.noteUnreadInput;
  const hold = useId();
  const [text, setText] = useState(() => show(value));
  const [error, setError] = useState<string | null>(null);
  const [seen, setSeen] = useState<unknown>(value);
  if (!deepEqual(value, seen)) {
    setSeen(value);
    setText(show(value));
    setError(null);
  }
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
    if (error === null) note?.(hold, null);
  }, [error, hold, note]);
  useEffect(() => () => note?.(hold, null), [hold, note]);

  return (
    <label className="flex flex-col gap-0.5 text-xs min-w-0">
      <span className="text-text-muted">{title}</span>
      <input
        aria-label={label}
        aria-invalid={error || flag ? true : undefined}
        className={`${INPUT}${mono ? " font-mono" : ""}`}
        value={text}
        placeholder={placeholder}
        onChange={(e) => {
          const next = e.target.value;
          setText(next);
          const result = read(next);
          if ("error" in result) {
            setError(result.error);
            note?.(hold, `${label}: ${result.error}`);
            return;
          }
          setError(null);
          setSeen(result.value);
          onValue(result.value);
        }}
      />
      {(error || flag) && (
        <span className="text-[11px] text-status-red" role="alert">
          {error ?? flag}
        </span>
      )}
    </label>
  );
}

/** Under a field that can be empty: what an empty value it holds stands in
 *  place of, and the buttons that unset the field or set it empty. */
function EmptyControls({
  step,
  field,
  position,
  vocabulary,
  onStep,
}: {
  step: StepValue;
  field: PackStepField;
  position: number;
  vocabulary: PackStepVocabulary;
  onStep: (next: StepValue) => void;
}) {
  const empty = emptyValue(field);
  if (empty === undefined) return null;
  const set = owns(step, field.name);
  const inherited = inheritedValue(step, field, vocabulary);
  const word = empty === null ? "none" : "empty";
  const put = (next: unknown) => onStep(withField(step, field.name, next, vocabulary));
  const emptyHeld = set && isEmptyValue(step[field.name]);
  const canEmpty = !set && !deepEqual(empty, inherited);
  if (!set && !canEmpty) return null;
  return (
    <div className="flex flex-wrap items-center gap-2 text-[11px]">
      {emptyHeld && (
        <span className="text-status-orange" data-pack-step-set-empty={field.name}>
          {deepEqual(empty, inherited)
            ? `set to ${word}`
            : `set to ${word}, in place of the shipped ${readableValue(inherited)}`}
        </span>
      )}
      {set ? (
        <button
          type="button"
          className={BUTTON}
          aria-label={`Unset ${field.name} of step ${position}`}
          onClick={() => put(undefined)}
        >
          Unset
        </button>
      ) : (
        <button
          type="button"
          className={BUTTON}
          aria-label={`Set ${field.name} of step ${position} to ${word}`}
          onClick={() => put(empty)}
        >
          {`Set to ${word}`}
        </button>
      )}
    </div>
  );
}

/** The template's arguments as name and value rows. A row that cannot be
 *  written yet (no name, a name given twice) holds Apply; a value that is not
 *  a string is shown and kept, and edited in the JSON view. */
function ArgumentsEditor({
  position,
  template,
  vocabulary,
  onTemplate,
}: {
  position: number;
  template: unknown;
  vocabulary: PackStepVocabulary;
  onTemplate: (value: Record<string, unknown> | undefined) => void;
}) {
  const ctx = useOptionalSettingsContext();
  const note = ctx?.noteUnreadInput;
  const hold = useId();
  const placeholders = useId();
  const [rows, setRows] = useState<ArgumentRow[]>(() => argumentRows(template));
  const [error, setError] = useState<string | null>(null);
  const [seen, setSeen] = useState<unknown>(template);
  if (!deepEqual(template, seen)) {
    setSeen(template);
    setRows(argumentRows(template));
    setError(null);
  }
  const generation = ctx?.discardGeneration ?? 0;
  const [seenGeneration, setSeenGeneration] = useState(generation);
  if (generation !== seenGeneration) {
    setSeenGeneration(generation);
    if (error !== null) {
      setRows(argumentRows(template));
      setError(null);
    }
  }
  useEffect(() => {
    if (error === null) note?.(hold, null);
  }, [error, hold, note]);
  useEffect(() => () => note?.(hold, null), [hold, note]);

  const commit = (next: ArgumentRow[]) => {
    setRows(next);
    const read = readArgumentRows(next);
    if ("error" in read) {
      setError(read.error);
      note?.(hold, `step ${position} arguments: ${read.error}`);
      return;
    }
    setError(null);
    const value = next.length > 0 ? read.value : undefined;
    setSeen(value);
    onTemplate(value);
  };
  const rule = placeholderRule(vocabulary);

  return (
    <fieldset className="border border-border rounded p-2 space-y-1">
      <legend className="text-[11px] text-text-muted px-1">Arguments</legend>
      <p className="text-[11px] text-text-muted">
        A value may name{" "}
        {vocabulary.placeholders.map((term, i) => (
          <span key={term.name}>
            {i > 0 && ", "}
            <code className="font-mono">{`{${term.name}}`}</code> ({term.meaning})
          </span>
        ))}
        . No arguments: the tool&rsquo;s declared path and hash arguments take the sample&rsquo;s.
      </p>
      {!rule && (
        <p className="text-[11px] text-status-orange">
          The placeholder rule the API serves does not read here; the save still checks it.
        </p>
      )}
      <datalist id={placeholders}>
        {vocabulary.placeholders.map((term) => (
          <option key={term.name} value={`{${term.name}}`} />
        ))}
      </datalist>
      <ul className="space-y-1">
        {rows.map((row, i) => {
          const flagged = unknownPlaceholders({ [row.name]: row.value }, vocabulary);
          const n = i + 1;
          return (
            <li key={i} className="space-y-0.5" data-pack-step-argument={row.name}>
              <div className="flex flex-wrap items-center gap-1">
                <input
                  aria-label={`step ${position} argument ${n} name`}
                  className={`${INPUT} font-mono sm:w-40 sm:flex-none`}
                  value={row.name}
                  placeholder="argument"
                  onChange={(e) => commit(replaceItem(rows, i, { ...row, name: e.target.value }))}
                />
                {typeof row.value === "string" ? (
                  <input
                    aria-label={`step ${position} argument ${n} value`}
                    aria-invalid={flagged.length > 0 ? true : undefined}
                    className={`${INPUT} font-mono flex-1`}
                    value={row.value}
                    list={placeholders}
                    onChange={(e) => commit(replaceItem(rows, i, { ...row, value: e.target.value }))}
                  />
                ) : (
                  <span className="flex-1 text-[11px] text-text-secondary">
                    <code className="font-mono break-all">{shownValue(row.value)}</code>{" "}
                    <span className="text-text-muted">(not text: kept as written, edited as JSON)</span>
                  </span>
                )}
                <button
                  type="button"
                  className={BUTTON}
                  aria-label={`Remove argument ${n} of step ${position}`}
                  onClick={() => commit(dropItem(rows, i))}
                >
                  Remove
                </button>
              </div>
              {flagged.map((found, k) => (
                <p key={k} className="text-[11px] text-status-red" role="alert">
                  {placeholderMessage(found, vocabulary)}
                </p>
              ))}
            </li>
          );
        })}
      </ul>
      {error && (
        <p className="text-[11px] text-status-red" role="alert">
          {error}
        </p>
      )}
      <button
        type="button"
        className={BUTTON}
        onClick={() => commit([...rows, { name: "", value: "" }])}
      >
        Add argument
      </button>
    </fieldset>
  );
}

/** One field the form has no control of its own for, drawn by its served type. */
function GenericField({
  step,
  field,
  position,
  vocabulary,
  onStep,
}: {
  step: StepValue;
  field: PackStepField;
  position: number;
  vocabulary: PackStepVocabulary;
  onStep: (next: StepValue) => void;
}) {
  const value = step[field.name];
  const set = owns(step, field.name);
  const inherited = inheritedValue(step, field, vocabulary);
  const where = standing(step, vocabulary);
  const placeholder = unsetSays(inherited, where);
  const cleared = clearedValue(step, field, vocabulary);
  const label = `step ${position} ${field.name}`;
  const put = (next: unknown) => onStep(withField(step, field.name, next, vocabulary));
  // A value of another type than the served one is shown as it is, never
  // drawn into a control that would put something else in its place.
  const fits = value === undefined || fitsField(value, field);
  const controls = (
    <EmptyControls
      step={step}
      field={field}
      position={position}
      vocabulary={vocabulary}
      onStep={onStep}
    />
  );

  if (field.name === "renderer" && fits) {
    const current = typeof value === "string" ? value : "";
    const known = vocabulary.renderers.some((term) => term.name === current);
    const shippedRenderer = typeof inherited === "string" ? inherited : "";
    const chosen = !set ? RENDERER_UNSET : current === "" ? RENDERER_EMPTY : current;
    return (
      <label className="flex flex-col gap-0.5 text-xs min-w-0">
        <span className="text-text-muted">{field.name}</span>
        <select
          aria-label={label}
          className={INPUT}
          value={chosen}
          onChange={(e) => {
            const picked = e.target.value;
            put(picked === RENDERER_UNSET ? undefined : picked === RENDERER_EMPTY ? "" : picked);
          }}
        >
          <option value={RENDERER_UNSET}>
            {shippedRenderer ? `unset: shipped ${shippedRenderer}` : "unset: the generic line"}
          </option>
          {(shippedRenderer || (set && current === "")) && (
            <option value={RENDERER_EMPTY}>
              {shippedRenderer
                ? `empty: the generic line, in place of the shipped ${shippedRenderer}`
                : "empty: the generic line"}
            </option>
          )}
          {vocabulary.renderers.map((term) => (
            <option key={term.name} value={term.name} title={term.meaning}>
              {term.name}
            </option>
          ))}
          {set && current && !known && (
            <option value={current}>{`${current} (not a renderer the API serves)`}</option>
          )}
        </select>
      </label>
    );
  }
  if (field.type === "string" && fits) {
    return (
      <div className="space-y-0.5 min-w-0">
        <TextBox
          title={field.name}
          label={label}
          value={value}
          show={(v) => (typeof v === "string" ? v : "")}
          read={(text) => readText(text, cleared)}
          placeholder={placeholder}
          mono
          onValue={put}
        />
        {controls}
      </div>
    );
  }
  if ((field.type === "number" || field.type === "integer") && fits) {
    return (
      <div className="space-y-0.5 min-w-0">
        <TextBox
          title={field.name}
          label={label}
          value={value}
          show={(v) => (typeof v === "number" ? String(v) : "")}
          read={(text) => readNumber(text, field, cleared)}
          placeholder={placeholder}
          flag={typeof value === "number" ? boundProblem(value, field) : ""}
          onValue={put}
        />
        {controls}
      </div>
    );
  }
  if (field.type === "array" && field.items === "string" && fits) {
    return (
      <div className="space-y-0.5 min-w-0">
        <TextBox
          title={`${field.name} (separated by commas)`}
          label={label}
          value={value}
          show={(v) => (Array.isArray(v) ? v.join(", ") : "")}
          read={(text) => readNames(text, cleared)}
          placeholder={placeholder}
          mono
          onValue={put}
        />
        {controls}
      </div>
    );
  }
  return (
    <div className="text-xs min-w-0">
      <span className="text-text-muted">{field.name}</span>{" "}
      <code className="font-mono break-all">{set ? shownValue(value) : placeholder}</code>{" "}
      <span className="text-[11px] text-text-muted">(edited as JSON)</span>
    </div>
  );
}

/** What the card's badge says of the step's standing. */
function standingWords(where: Standing, id: string, display: unknown): string {
  if (where === "own") return "a step of your own";
  const named = typeof display === "string" && display ? ` (${display})` : "";
  return where === "over"
    ? `changes the shipped step ${id}${named} in its place`
    : `replaces the shipped step ${id}${named} at its place: nothing of it is kept but its id and place`;
}

function StepCard({
  step,
  index,
  count,
  vocabulary,
  servers,
  problem,
  leftOut,
  probe,
  onListTools,
  onStep,
  onMove,
  onDrop,
}: {
  step: StepValue;
  index: number;
  count: number;
  vocabulary: PackStepVocabulary;
  servers: Record<string, McpServerEntry>;
  problem?: string;
  leftOut?: string;
  probe?: Probe;
  onListTools: (server: string) => void;
  onStep: (next: StepValue) => void;
  onMove: (to: number) => void;
  onDrop: () => void;
}) {
  const tools = useId();
  const position = index + 1;
  const id = stepId(step);
  const name = id || `at ${position}`;
  const shipped = shippedSteps(vocabulary).get(id);
  const where = standing(step, vocabulary);
  const server = typeof step.server === "string" ? step.server : "";
  const tool = typeof step.tool === "string" ? step.tool : "";
  const result = probe && probe !== "running" ? probe : undefined;
  const listed = result?.tools ?? null;
  const offer = offeredTools({ step, servers, listed, vocabulary });
  const said = toolNote({ step, servers, listed, vocabulary });
  const enabled = runs(step, vocabulary);
  const stateNote = stateKeyNote(step, vocabulary);
  const cell = tool ? capabilityCells(result).get(tool) : undefined;
  // A control of its own is drawn for a field the API serves whose stored
  // value it can show; any other value is named in `mistyped` instead.
  const has = (fieldName: string) => {
    const field = fieldOf(vocabulary, fieldName);
    return field !== undefined && (step[fieldName] === undefined || fitsField(step[fieldName], field));
  };
  const mistyped = typeProblems(step, vocabulary);
  const budget = has("budget_seconds") ? fieldOf(vocabulary, "budget_seconds") : undefined;
  const formatsField = has("formats") ? fieldOf(vocabulary, "formats") : undefined;
  const toolField = fieldOf(vocabulary, "tool");
  const inheritedTool = toolField ? inheritedValue(step, toolField, vocabulary) : "";
  const flags = vocabulary.fields.filter(
    (f) => f.type === "boolean" && !OWN_CONTROLS.includes(f.name) && has(f.name),
  );
  const more = vocabulary.fields.filter(
    (f) => !OWN_CONTROLS.includes(f.name) && f.type !== "boolean",
  );
  const [moreOpen] = useState(() => more.some((f) => owns(step, f.name)));
  const strange = unknownFields(step, vocabulary);
  const showArguments = has("arguments") && (server !== "" || step.arguments !== undefined);
  const put = (field: string, value: unknown) => onStep(withField(step, field, value, vocabulary));

  return (
    <fieldset
      className="border border-border rounded p-2 space-y-2"
      data-pack-step={id || `#${index}`}
      data-pack-step-standing={where}
    >
      <legend className="sr-only">{`Step ${position}: ${name}`}</legend>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11px] text-text-muted">{position}.</span>
        <label className="flex items-center gap-1 text-xs min-w-0">
          <span className="text-text-muted">id</span>
          <input
            aria-label={`step ${position} id`}
            aria-invalid={problem ? true : undefined}
            className={`${BOX} font-mono w-48`}
            value={id}
            onChange={(e) => put("id", e.target.value)}
          />
        </label>
        <span className="text-[11px] text-text-muted" data-pack-step-badge>
          {standingWords(where, id, shipped?.display_name)}
        </span>
        {flags.map((field) => {
          // Back at what it inherits, the field is unset again rather than
          // written out with the value it would have anyway.
          const inherited = Boolean(inheritedValue(step, field, vocabulary));
          const held = step[field.name];
          return (
            <label key={field.name} className="flex items-center gap-1 text-xs">
              <input
                type="checkbox"
                aria-label={`step ${position} ${field.name}`}
                checked={typeof held === "boolean" ? held : inherited}
                onChange={(e) =>
                  put(field.name, e.target.checked === inherited ? undefined : e.target.checked)
                }
              />
              {field.name}
            </label>
          );
        })}
        <div className="ml-auto flex gap-1">
          <button
            type="button"
            className={BUTTON}
            aria-label={`Move step ${name} up`}
            disabled={index === 0}
            onClick={() => onMove(index - 1)}
          >
            Up
          </button>
          <button
            type="button"
            className={BUTTON}
            aria-label={`Move step ${name} down`}
            disabled={index === count - 1}
            onClick={() => onMove(index + 1)}
          >
            Down
          </button>
          <button type="button" className={BUTTON} aria-label={`Drop step ${name}`} onClick={onDrop}>
            Drop
          </button>
        </div>
      </div>
      {problem && (
        <p className="text-[11px] text-status-red" role="alert">
          {problem}
        </p>
      )}
      {leftOut && (
        <p className="text-[11px] text-status-orange" data-pack-step-left-out-mark={id}>
          {`Left out as stored: ${leftOut}`}
        </p>
      )}
      {mistyped.map((line) => (
        <p key={line} className="text-[11px] text-status-orange" data-pack-step-mistyped>
          {line}
        </p>
      ))}
      {stateNote && (
        <p className="text-[11px] text-text-muted" data-pack-step-state-key-note>
          {stateNote}
        </p>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)] gap-2">
        {has("server") && (
          <label className="flex flex-col gap-0.5 text-xs min-w-0">
            <span className="text-text-muted">Server</span>
            <select
              aria-label={`step ${position} server`}
              className={INPUT}
              value={server}
              onChange={(e) => put("server", e.target.value === "" ? undefined : e.target.value)}
            >
              <option value="">none: one of the platform&rsquo;s own steps</option>
              {Object.keys(servers).map((key) => (
                <option key={key} value={key}>
                  {ownEntry(servers, key)?.enabled === false ? `${key} (disabled)` : key}
                </option>
              ))}
              {server && ownEntry(servers, server) === undefined && (
                <option value={server}>{`${server} (not a configured server)`}</option>
              )}
            </select>
          </label>
        )}
        {has("tool") && (
          <div className="flex flex-col gap-0.5 text-xs min-w-0">
            <span className="text-text-muted">Tool</span>
            <div className="flex items-center gap-1">
              <input
                aria-label={`step ${position} tool`}
                aria-invalid={said?.level === "error" ? true : undefined}
                className={`${INPUT} font-mono`}
                list={tools}
                value={tool}
                placeholder={
                  typeof inheritedTool === "string" && inheritedTool
                    ? `shipped: ${inheritedTool}`
                    : where === "over"
                      ? `shipped: ${id}`
                      : "the tool's name"
                }
                onChange={(e) => put("tool", e.target.value === "" ? undefined : e.target.value)}
              />
              {server && (
                <button
                  type="button"
                  className={`${BUTTON} shrink-0`}
                  disabled={probe === "running"}
                  onClick={() => onListTools(server)}
                >
                  {probe === "running" ? "Listing…" : "List tools"}
                </button>
              )}
            </div>
            <datalist id={tools}>
              {offer.offered.map((offered) => (
                <option key={offered} value={offered} />
              ))}
            </datalist>
            {said && (
              <span
                className={`text-[11px] ${said.level === "error" ? "text-status-red" : "text-status-orange"}`}
                data-pack-step-tool-note={said.level}
              >
                {said.text}
              </span>
            )}
            {offer.refused.length > 0 && (
              <span className="text-[11px] text-text-muted" data-pack-step-tools-refused>
                {`Not offered, as the save refuses them${
                  enabled ? "" : " once the step is enabled"
                }: ${offer.refused.map((held) => held.reason).join("; ")}`}
              </span>
            )}
            {cell && cell.available === false && (
              <span className="text-[11px] text-status-orange">
                {`${server} says it cannot run this tool on its host: ${unavailableReason(cell)}`}
              </span>
            )}
            {result && !result.ok && (
              <span className="text-[11px] text-status-red">
                {`List tools failed: ${probeDetail(result.detail)}`}
              </span>
            )}
            {result && result.ok && listed !== null && listed.length === 0 && (
              <span className="text-[11px] text-text-muted">{`${server} reported no tools`}</span>
            )}
          </div>
        )}
      </div>

      {showArguments && (
        <ArgumentsEditor
          position={position}
          template={step.arguments}
          vocabulary={vocabulary}
          onTemplate={(value) => put("arguments", value)}
        />
      )}

      <div className="grid grid-cols-1 sm:grid-cols-[minmax(0,10rem)_minmax(0,1fr)] gap-2">
        {budget && (
          <div className="space-y-0.5 min-w-0">
            <TextBox
              title="Budget (seconds)"
              label={`step ${position} budget_seconds`}
              value={step.budget_seconds}
              show={(v) => (typeof v === "number" ? String(v) : "")}
              read={(text) => readNumber(text, budget, clearedValue(step, budget, vocabulary))}
              placeholder={unsetSays(inheritedValue(step, budget, vocabulary), where)}
              flag={
                typeof step.budget_seconds === "number"
                  ? boundProblem(step.budget_seconds, budget)
                  : ""
              }
              onValue={(value) => put("budget_seconds", value)}
            />
            <EmptyControls
              step={step}
              field={budget}
              position={position}
              vocabulary={vocabulary}
              onStep={onStep}
            />
          </div>
        )}
        {formatsField && (
          <FormatsField
            step={step}
            field={formatsField}
            position={position}
            where={where}
            vocabulary={vocabulary}
            onStep={onStep}
          />
        )}
      </div>

      {more.length > 0 && (
        <details open={moreOpen}>
          <summary className="text-[11px] text-accent-strong cursor-pointer">More fields</summary>
          <div className="mt-1 grid grid-cols-1 sm:grid-cols-2 gap-2">
            {more.map((field) => (
              <GenericField
                key={field.name}
                step={step}
                field={field}
                position={position}
                vocabulary={vocabulary}
                onStep={onStep}
              />
            ))}
          </div>
        </details>
      )}

      {strange.length > 0 && (
        <div className="text-[11px] text-status-orange space-y-0.5" data-pack-step-unknown-fields>
          <p>Fields the API&rsquo;s step model does not know, kept as stored:</p>
          <ul className="space-y-0.5">
            {strange.map((field) => (
              <li key={field} className="flex flex-wrap items-center gap-1" data-pack-step-unknown-field={field}>
                <code className="font-mono">{field}</code>
                <code className="font-mono break-all text-text-secondary">{shownValue(step[field])}</code>
                <button
                  type="button"
                  className={BUTTON}
                  aria-label={`Remove field ${field} of step ${position}`}
                  onClick={() => put(field, undefined)}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </fieldset>
  );
}

/** The step's formats: its own list, an explicit "every format", or, unset,
 *  what it holds in force. The boxes show what is in force; returning them to
 *  what the step inherits unsets the field, and emptying a list that stands
 *  over a shipped one writes "every format" rather than bringing that back. */
function FormatsField({
  step,
  field,
  position,
  where,
  vocabulary,
  onStep,
}: {
  step: StepValue;
  field: PackStepField;
  position: number;
  where: Standing;
  vocabulary: PackStepVocabulary;
  onStep: (next: StepValue) => void;
}) {
  const set = owns(step, field.name);
  const stored = Array.isArray(step.formats)
    ? step.formats.filter((v): v is string => typeof v === "string")
    : [];
  const inheritedRaw = inheritedValue(step, field, vocabulary);
  const inherited = Array.isArray(inheritedRaw) ? inheritedRaw.map(String) : [];
  const ticked = set ? stored : inherited;
  const put = (next: unknown) => onStep(withField(step, field.name, next, vocabulary));
  const line = set
    ? stored.length > 0
      ? stored.join(", ")
      : inherited.length > 0
        ? `set to none: every format, in place of the shipped ${inherited.join(", ")}`
        : "set to none: every format"
    : inherited.length > 0
      ? `unset: ${where === "over" ? "shipped" : "default"} ${inherited.join(", ")}`
      : "every format";
  return (
    <fieldset className="text-xs min-w-0">
      <legend className="text-text-muted">Formats</legend>
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-[11px] text-text-secondary" data-pack-step-formats>
          {line}
        </p>
        {set ? (
          <button
            type="button"
            className={BUTTON}
            aria-label={`Unset formats of step ${position}`}
            onClick={() => put(undefined)}
          >
            Unset
          </button>
        ) : (
          inherited.length > 0 && (
            <button
              type="button"
              className={BUTTON}
              aria-label={`Set formats of step ${position} to every format`}
              onClick={() => put([])}
            >
              Every format
            </button>
          )
        )}
      </div>
      <details>
        <summary className="text-[11px] text-accent-strong cursor-pointer">Choose formats</summary>
        <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
          {choiceRows(vocabulary.formats, ticked).map(({ key, known }) => (
            <label key={key} className="flex items-center gap-1 text-[11px] text-text-secondary">
              <input
                type="checkbox"
                aria-label={`step ${position} format ${key}`}
                checked={ticked.includes(key)}
                onChange={(e) => {
                  const next = toggleChoice(ticked, key, e.target.checked);
                  put(deepEqual(next, inherited) ? undefined : next);
                }}
              />
              <span className="font-mono">{key}</span>
              {!known && <span className="text-status-orange">(not a routed format)</span>}
            </label>
          ))}
        </div>
      </details>
    </fieldset>
  );
}

function AddStep({
  steps,
  vocabulary,
  onAdd,
}: {
  steps: readonly StepValue[];
  vocabulary: PackStepVocabulary;
  onAdd: (id: string) => void;
}) {
  const [id, setId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const list = useId();
  const declared = new Set(steps.map(stepId));
  const offered = [...shippedSteps(vocabulary).keys()].filter((key) => !declared.has(key));
  const add = () => {
    const wanted = id.trim();
    const problem = newStepError(wanted, steps, vocabulary);
    if (problem) {
      setError(problem);
      return;
    }
    onAdd(wanted);
    setId("");
    setError(null);
  };
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <input
          aria-label="New step id"
          className={`${INPUT} font-mono sm:w-72 sm:flex-none`}
          list={list}
          value={id}
          placeholder="a new id, or a shipped step's id to change it"
          onChange={(e) => {
            setId(e.target.value);
            setError(null);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
        />
        <datalist id={list}>
          {offered.map((key) => (
            <option key={key} value={key} />
          ))}
        </datalist>
        <button type="button" className={BUTTON} onClick={add}>
          Add step
        </button>
      </div>
      {error && (
        <p className="text-[11px] text-status-red" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

/** One List tools answer, with the server's settings it was asked under. */
interface Listing {
  config: McpServerEntry | undefined;
  result: Probe;
}

function StepsForm({
  steps,
  vocabulary,
  servers,
  leftOut,
  onChange,
}: {
  steps: StepValue[];
  vocabulary: PackStepVocabulary;
  servers: Record<string, McpServerEntry>;
  leftOut: Map<string, string>;
  onChange: (value: StepValue[]) => void;
}) {
  // Keys follow a step through a move and survive an edit of its id; a list
  // whose length changed from outside (a discard, the JSON view) is keyed afresh.
  const [keys, setKeys] = useState<string[]>(() => stepKeys(steps));
  const fresh = useRef(0);
  const drawn = keys.length === steps.length ? keys : stepKeys(steps);
  if (keys.length !== steps.length) setKeys(drawn);
  // A listing describes the server as it was configured when it was asked: one
  // whose server's staged settings changed since is dropped, not shown as current.
  const [listings, setListings] = useState<Record<string, Listing>>({});
  const stale = staleListings(listings, servers);
  if (stale.length > 0) {
    setListings((held) => {
      const next = { ...held };
      for (const key of stale) delete next[key];
      return next;
    });
  }
  const problems = idProblems(steps, vocabulary);

  const update = (next: StepValue[], nextKeys: string[]) => {
    setKeys(nextKeys);
    onChange(next);
  };
  const listTools = async (server: string) => {
    const config = ownEntry(servers, server);
    const settle = (result: Probe) =>
      setListings((held) => {
        const asked = ownEntry(held, server);
        return asked && deepEqual(asked.config, config)
          ? { ...held, [server]: { config, result } }
          : held;
      });
    setListings((held) => ({ ...held, [server]: { config, result: "running" } }));
    try {
      settle(await api.testMcpServer(server, { "core.mcp.servers": servers }));
    } catch (e) {
      settle({
        ok: false,
        latency_ms: 0,
        detail: getErrorMessage(e),
        models: null,
        tools: null,
        details: null,
      });
    }
  };

  return (
    <div className="space-y-2">
      {steps.length === 0 ? (
        <p className="text-xs text-text-muted">
          No steps of your own: the {vocabulary.shipped.length} shipped steps run as they ship.
        </p>
      ) : (
        <ol className="space-y-2">
          {steps.map((step, index) => (
            <li key={drawn[index]}>
              <StepCard
                step={step}
                index={index}
                count={steps.length}
                vocabulary={vocabulary}
                servers={servers}
                problem={problems.get(index)}
                leftOut={leftOut.get(stepId(step) || `#${index}`)}
                probe={
                  typeof step.server === "string" && step.server
                    ? ownEntry(listings, step.server)?.result
                    : undefined
                }
                onListTools={(server) => void listTools(server)}
                onStep={(next) => update(replaceItem(steps, index, next), drawn)}
                onMove={(to) => update(moveItem(steps, index, to), moveItem(drawn, index, to))}
                onDrop={() => update(dropItem(steps, index), dropItem(drawn, index))}
              />
            </li>
          ))}
        </ol>
      )}
      <AddStep
        steps={steps}
        vocabulary={vocabulary}
        onAdd={(id) => {
          fresh.current += 1;
          update([...steps, { id }], [...drawn, `new#${fresh.current}`]);
        }}
      />
    </div>
  );
}

/** The whole list as JSON. Text that does not read holds Apply, and the form
 *  cannot be opened over it. */
function StepsJson({
  value,
  label,
  onChange,
  onUnread,
}: {
  value: unknown;
  label: string;
  onChange: (value: unknown) => void;
  onUnread: (unread: boolean) => void;
}) {
  const ctx = useOptionalSettingsContext();
  const note = ctx?.noteUnreadInput;
  const hold = useId();
  const show = (v: unknown) => JSON.stringify(v ?? [], null, 2);
  const [text, setText] = useState(() => show(value));
  const [error, setError] = useState<string | null>(null);
  const [seen, setSeen] = useState<unknown>(value);
  if (!deepEqual(value, seen)) {
    setSeen(value);
    setText(show(value));
    setError(null);
  }
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
    onUnread(error !== null);
    if (error === null) note?.(hold, null);
  }, [error, hold, note, onUnread]);
  useEffect(() => () => note?.(hold, null), [hold, note]);

  return (
    <div>
      <textarea
        aria-label={`${label} as JSON`}
        aria-invalid={error ? true : undefined}
        className={`${INPUT} font-mono`}
        rows={Math.min(18, Math.max(4, text.split("\n").length))}
        value={text}
        onChange={(e) => {
          const next = e.target.value;
          setText(next);
          try {
            const parsed: unknown = JSON.parse(next);
            setError(null);
            setSeen(parsed);
            onChange(parsed);
          } catch (err) {
            const message = getErrorMessage(err);
            setError(message);
            note?.(hold, `${label}: invalid JSON: ${message}`);
          }
        }}
      />
      {error && (
        <div className="text-[11px] text-status-red mt-1" role="alert">
          Invalid JSON: {error}
        </div>
      )}
    </div>
  );
}

export default function PackStepsEditor({
  entry,
  current,
  staged,
  errors,
  servers,
  onChange,
}: {
  entry: CatalogEntry;
  current?: SettingValue;
  staged: unknown;
  errors: Record<string, string>;
  servers: Record<string, McpServerEntry>;
  onChange: (value: unknown) => void;
}) {
  const vocabulary = entry.pack_step_vocabulary ?? null;
  const shown = staged !== undefined ? staged : (current?.value ?? entry.default);
  const steps = readSteps(shown);
  const [asJson, setAsJson] = useState(false);
  const [unread, setUnread] = useState(false);
  // A value the form cannot draw opens the JSON view, which stays open once
  // the typing there makes it a list again: the box is not taken away mid-edit.
  if (vocabulary !== null && steps === null && !asJson) setAsJson(true);
  const schema = useOptionalSettingsContext()?.schema;
  const leftOut = new Map(
    leftOutSteps(schema?.pack_steps_left_out).map(({ step, reason }) => [step, reason]),
  );
  const formable = vocabulary !== null && steps !== null;
  const json = !formable || asJson;
  const nested = nestedErrors(errors, entry.key);

  return (
    <div className="space-y-2" data-pack-steps-editor={json ? "json" : "form"}>
      {formable && (
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            className={BUTTON}
            aria-pressed={asJson}
            disabled={asJson && unread}
            title={asJson && unread ? "The JSON does not read; fix it first" : undefined}
            onClick={() => setAsJson((v) => !v)}
          >
            {asJson ? "Edit in the form" : "Edit as JSON (advanced)"}
          </button>
          <span className="text-[11px] text-text-muted">Both views edit the same list.</span>
        </div>
      )}
      {vocabulary === null && (
        <p className="text-[11px] text-text-muted">
          This API serves no step vocabulary, so the steps are edited as JSON.
        </p>
      )}
      {vocabulary !== null && steps === null && (
        <p className="text-[11px] text-status-orange">
          The value is not a list of steps, so it is shown as JSON; the save says what it
          refuses in it.
        </p>
      )}
      {json || vocabulary === null || steps === null ? (
        <StepsJson value={shown} label={entry.title} onChange={onChange} onUnread={setUnread} />
      ) : (
        <StepsForm
          steps={steps}
          vocabulary={vocabulary}
          servers={servers}
          leftOut={leftOut}
          onChange={onChange}
        />
      )}
      {nested.length > 0 && (
        <ul className="text-[11px] text-status-red space-y-0.5" role="alert">
          {nested.map(([at, message]) => (
            <li key={at}>
              <span className="font-mono">{at.slice(entry.key.length + 1)}</span>
              {`: ${message}`}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
