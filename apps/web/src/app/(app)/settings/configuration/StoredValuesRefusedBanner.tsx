"use client";

import type { SettingsSchema } from "@/types/settings";
import { useOptionalSettingsContext } from "./SettingsContext";

export interface RefusedRow {
  key: string;
  title: string;
  reason: string;
}

/** What the settings-wide banner says above every page while a stored value is refused. */
export const REFUSED_HEADLINE =
  "Stored settings values are refused, so analyses and the routes that read the settings " +
  "fail until each is fixed or reset here:";

/** Each refused stored value the API serves, with its setting's title. */
export function refusedRows(schema: SettingsSchema | null | undefined): RefusedRow[] {
  const served = schema?.stored_values_refused;
  if (!served || typeof served !== "object") return [];
  const titles = new Map<string, string>();
  for (const group of schema?.groups ?? []) {
    for (const entry of group.entries) titles.set(entry.key, entry.title);
  }
  return Object.entries(served).map(([key, reason]) => ({
    key,
    title: titles.get(key) ?? key,
    reason: typeof reason === "string" ? reason : "",
  }));
}

/** Above every settings page: the stored values nothing that runs will accept. */
export default function StoredValuesRefusedBanner() {
  const rows = refusedRows(useOptionalSettingsContext()?.schema);
  if (rows.length === 0) return null;
  return (
    <div
      role="alert"
      data-stored-values-refused
      className="mb-4 border border-status-red rounded px-3 py-2 text-[11px] text-status-red"
    >
      <p>{REFUSED_HEADLINE}</p>
      <ul className="mt-1 space-y-0.5">
        {rows.map((row) => (
          <li key={row.key}>
            {row.title} (<span className="font-mono">{row.key}</span>)
            {row.reason && <span>: {row.reason}</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}
