"use client";

import type { CatalogEntry, SettingValue } from "@/types/settings";
import { ToolFactsBox } from "./DeclarationFields";
import { usableFields } from "./declarationFields";
import { useOptionalSettingsContext } from "./SettingsContext";
import type { ToolFactsChanges } from "./toolFactsChanges";

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
 * carry a change and resets one to shipped.
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
  const fields = usableFields(useOptionalSettingsContext()?.schema?.tool_declaration_fields);
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
      onChanges={(next) => {
        // Nothing changed of what ships, with nothing stored or staged:
        // nothing to stage.
        if (Object.keys(next).length === 0 && changes === undefined) return;
        onChange(next);
      }}
    />
  );
}
