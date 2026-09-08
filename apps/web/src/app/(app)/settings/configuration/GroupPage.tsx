"use client";

import { useCallback, useMemo, useState } from "react";
import type { CatalogEntry } from "@/types/settings";
import FieldRow from "./FieldRow";
import { buildFieldRowProps } from "./fieldRowProps";
import GroupHeader from "./GroupHeader";
import RestSandboxEditor from "./RestSandboxEditor";
import { resolveGroup } from "./sections";
import { useSettingsContext, type SettingsContextValue } from "./SettingsContext";

/** Groups whose first row picks a provider and whose remaining rows belong to
 *  whichever provider that is. */
const PROVIDER_GROUPS = new Set(["static", "sandbox"]);

/** Titles the plain capitalisation of a choice id would get wrong. */
const PROVIDER_TITLE: Record<string, string> = {
  capa_yara: "capa + YARA",
  generic_mcp: "Generic MCP server",
  cape2: "CAPE",
  r2: "radare2",
  ghidra: "Ghidra",
  rest: "REST sandbox",
};

/** What a provider choice that reveals no fields of its own actually means,
 *  so the page says something rather than ending at the selector. */
const EMPTY_PROVIDER_NOTE: Record<string, string> = {
  none: "No static provider: the static analyst works from the pre-extracted data only.",
  mock: "Mock sandbox: built-in fixture reports stand in for a detonation.",
};

function providerTitle(choice: string): string {
  return PROVIDER_TITLE[choice] ?? choice.charAt(0).toUpperCase() + choice.slice(1);
}

function slug(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function Row({ ctx, entry }: { ctx: SettingsContextValue; entry: CatalogEntry }) {
  return <FieldRow {...buildFieldRowProps(ctx, entry)} />;
}

/** The "Advanced (N)" disclosure. Whether it starts open is decided once, on
 *  mount: a fold that re-opened itself every time a value inside it was
 *  staged could never be closed while editing. */
function AdvancedFold({
  ctx,
  testId,
  entries,
}: {
  ctx: SettingsContextValue;
  testId: string;
  entries: CatalogEntry[];
}) {
  const [defaultOpen] = useState(() =>
    entries.some((e) => e.key in ctx.pending || ctx.values[e.key]?.source === "ui")
  );
  return (
    <details data-testid={`advanced-${testId}`} open={defaultOpen} className="mt-2">
      <summary className="text-xs text-text-secondary cursor-pointer py-1">
        Advanced ({entries.length})
      </summary>
      <div>
        {entries.map((entry) => (
          <Row key={entry.key} ctx={ctx} entry={entry} />
        ))}
      </div>
    </details>
  );
}

/** One subgroup: its heading, its plain rows, then its advanced fold. */
function Subgroup({
  ctx,
  name,
  entries,
  foldId,
}: {
  ctx: SettingsContextValue;
  name: string | null;
  entries: CatalogEntry[];
  foldId: string;
}) {
  const plain = entries.filter((e) => !e.advanced);
  const advanced = entries.filter((e) => e.advanced);
  return (
    <div className="mb-4">
      {name && (
        <h3 className="text-[11px] uppercase tracking-wider text-text-muted mt-4 mb-1">{name}</h3>
      )}
      {plain.map((entry) => (
        <Row key={entry.key} ctx={ctx} entry={entry} />
      ))}
      {advanced.length > 0 && (
        <AdvancedFold ctx={ctx} testId={foldId} entries={advanced} />
      )}
    </div>
  );
}

/** Splits entries into subgroup buckets, the group's own (null) bucket first
 *  and the named ones in the order they first appear. */
function bySubgroup(entries: CatalogEntry[]): { name: string | null; entries: CatalogEntry[] }[] {
  const buckets: { name: string | null; entries: CatalogEntry[] }[] = [];
  const index = new Map<string, number>();
  for (const entry of entries) {
    const name = entry.subgroup ?? null;
    const id = name ?? "";
    const at = index.get(id);
    if (at === undefined) {
      index.set(id, buckets.length);
      buckets.push({ name, entries: [entry] });
    } else {
      buckets[at].entries.push(entry);
    }
  }
  return buckets.sort((a, b) => (a.name === null ? -1 : b.name === null ? 1 : 0));
}

export default function GroupPage({ section, group }: { section: string; group: string }) {
  const ctx = useSettingsContext();
  const { schema } = ctx;

  const resolved = useMemo(
    () => (schema ? resolveGroup(schema, section, group) : null),
    [schema, section, group]
  );

  const probeInputsStaged = useCallback(
    (probeId: string) => Object.keys(ctx.probeValues(probeId)).length > 0,
    [ctx]
  );

  const onProbe = useCallback(
    async (name: string) => {
      // Every staged input the probe consumes has to travel with it, wherever
      // the catalog files it: `core.llm.provider` lives in a different group
      // from the per-provider base URL and model leaves, so a group-local key
      // list would silently drop half of what the backend reads.
      const keys = Array.from(ctx.entries.values())
        .filter((e) => e.probe === name)
        .map((e) => e.key);
      const result = await ctx.probe(name, keys);
      if (result.models) ctx.setModels(result.models);
      return result;
    },
    [ctx]
  );

  if (!resolved) {
    return <p role="alert">No such settings group.</p>;
  }

  const sorted = [...resolved.entries].sort(
    (a, b) => a.order - b.order || a.key.localeCompare(b.key)
  );
  const probes = Array.from(
    new Set(sorted.map((e) => e.probe).filter((p): p is string => Boolean(p)))
  );
  const overriddenKeys = sorted.filter((e) => ctx.values[e.key]?.source === "ui");

  let shown = sorted.filter((e) => ctx.isVisible(e));
  if (ctx.onlyChanged) {
    shown = shown.filter((e) => e.key in ctx.pending || ctx.values[e.key]?.source === "ui");
  }

  const rest = shown.filter((e) => e.editor === "rest_sandbox");
  const rows = shown.filter((e) => e.editor !== "rest_sandbox");

  const isProviderGroup = PROVIDER_GROUPS.has(resolved.backendGroup);
  const selector = isProviderGroup
    ? rows.find(
        (e) =>
          e.order === -1 &&
          (e.choices_from === "static_providers" || e.choices_from === "sandbox_providers")
      )
    : undefined;
  const dependents = selector ? rows.filter((e) => e.key !== selector.key) : rows;
  const selectedProvider = selector ? String(ctx.effectiveValue(selector.key) ?? "") : "";

  const header = (
    <GroupHeader
      title={resolved.title}
      description={resolved.description}
      probes={probes}
      overridden={overriddenKeys.length > 0}
      overriddenCount={overriddenKeys.length}
      onProbe={onProbe}
      onResetGroup={() => ctx.resetGroup(resolved.backendGroup)}
      probeInputsStaged={probeInputsStaged}
    />
  );

  if (ctx.onlyChanged && rows.length === 0 && rest.length === 0) {
    return (
      <section>
        {header}
        <p className="text-sm text-text-muted">No overrides in this group</p>
      </section>
    );
  }

  const body = bySubgroup(dependents).map((bucket) => (
    <Subgroup
      key={bucket.name ?? "__group__"}
      ctx={ctx}
      name={bucket.name}
      entries={bucket.entries}
      foldId={bucket.name ? slug(bucket.name) : group}
    />
  ));

  return (
    <section>
      {header}
      {selector && <Row ctx={ctx} entry={selector} />}
      {selector && (dependents.length > 0 || rest.length > 0) && (
        <h3 className="text-sm font-medium text-text-primary mt-4 mb-1">
          {providerTitle(selectedProvider)} settings
        </h3>
      )}
      {selector &&
        dependents.length === 0 &&
        rest.length === 0 &&
        EMPTY_PROVIDER_NOTE[selectedProvider] && (
          <p className="text-sm text-text-secondary mt-3">
            {EMPTY_PROVIDER_NOTE[selectedProvider]}
          </p>
        )}
      {body}
      {rest.length > 0 && (
        <RestSandboxEditor
          entries={rest}
          values={ctx.values}
          pending={ctx.pending}
          errors={ctx.errors}
          onChange={ctx.stage}
          onUnstage={ctx.unstage}
          onReset={(k) => void ctx.reset(k)}
        />
      )}
    </section>
  );
}
