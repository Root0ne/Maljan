"use client";

import type { CatalogEntry } from "@/types/settings";
import { RestMappingTable } from "../../configuration/RestSandboxEditor";
import { useSettingsContext } from "../../configuration/SettingsContext";

const MAPPING_PREFIX = "core.sandbox.rest.mapping.";

/**
 * The sandbox guide's mapping step: the console's own report-mapping table,
 * with its paste-and-preview block, over the `core.sandbox.rest.mapping.*`
 * leaves. Nothing is copied — the guide and the console render one component,
 * so a JSONPath tried here is the JSONPath a job will run.
 */
export default function RestMappingStep() {
  const ctx = useSettingsContext();
  const entries = Array.from(ctx.entries.values()).filter((e: CatalogEntry) =>
    e.key.startsWith(MAPPING_PREFIX)
  );

  if (entries.length === 0) {
    return <p className="text-sm text-text-secondary">This sandbox has no report mapping.</p>;
  }

  return (
    <RestMappingTable
      entries={entries}
      values={ctx.values}
      pending={ctx.pending}
      errors={ctx.errors}
      onChange={ctx.stage}
      onUnstage={ctx.unstage}
      onReset={(k) => void ctx.reset(k)}
    />
  );
}
