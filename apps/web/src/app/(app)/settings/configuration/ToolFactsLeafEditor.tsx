"use client";

import type { CatalogEntry, SettingValue } from "@/types/settings";
import { ToolFactsBox } from "./DeclarationFields";
import { usableFields } from "./declarationFields";
import { useOptionalSettingsContext } from "./SettingsContext";
import { namesAnyTool, type ToolFactsChanges } from "./toolFactsChanges";

function asDeclarations(value: unknown): Record<string, Record<string, unknown>> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, Record<string, unknown>>)
    : {};
}

/**
 * A provider block's `tool_facts` leaf (`core.static.ghidra.tool_facts` …).
 *
 * The leaf stores the block's changes over the tool declarations it ships,
 * one tool at a time; the catalog default is what it ships. The same box as
 * a tool server's declaration shows them in force, lists the tools that
 * carry a change (marking one whose change does not validate over what
 * ships now) and resets one to shipped.
 */
export default function ToolFactsLeafEditor({
  entry,
  current,
  staged,
  onChange,
}: {
  entry: CatalogEntry;
  current: SettingValue | undefined;
  staged: unknown;
  onChange: (value: ToolFactsChanges) => void;
}) {
  const schema = useOptionalSettingsContext()?.schema;
  const fields = usableFields(schema?.tool_declaration_fields);
  // The block's dotted path, as the schema names its conflicting changes.
  const block = entry.key.replace(/^core\./, "").replace(/\.tool_facts$/, "");
  const stored = current?.source === "ui" ? current.value : undefined;
  const changes = (staged !== undefined ? staged : stored) as ToolFactsChanges | undefined;
  return (
    <ToolFactsBox
      id={entry.key}
      ariaLabel={entry.title}
      serverKey=""
      shipped={asDeclarations(entry.default)}
      changes={changes ?? undefined}
      fields={fields}
      conflicts={schema?.tool_facts_conflicts?.[block]}
      onChanges={(next) => {
        // Nothing changed of what ships, with nothing stored or staged:
        // nothing to stage.
        if (!namesAnyTool(next) && changes === undefined) return;
        onChange(next);
      }}
    />
  );
}
