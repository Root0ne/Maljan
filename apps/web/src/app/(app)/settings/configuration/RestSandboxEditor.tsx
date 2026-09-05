"use client";

import { useMemo, useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import type { CatalogEntry, MappingPreview, SettingValue } from "@/types/settings";
import FieldRow from "./FieldRow";

const SECTIONS: { title: string; prefix: string }[] = [
  { title: "Connection", prefix: "core.sandbox.rest.auth." },
  { title: "Submit", prefix: "core.sandbox.rest.submit." },
  { title: "Status", prefix: "core.sandbox.rest.status." },
  { title: "Report", prefix: "core.sandbox.rest.report." },
];
const MAPPING_PREFIX = "core.sandbox.rest.mapping.";

/**
 * The `sandbox.rest.*` leaves, grouped, with a mapping table that can be tried.
 *
 * Every field is still an ordinary catalog leaf rendered by `FieldRow`, so
 * staging, per-key reset and `.env` export work exactly as they do everywhere
 * else. What this adds is arrangement — four fieldsets instead of thirty flat
 * rows — and the preview: paste one of the sandbox's real responses, press the
 * button, and see per channel how many rows each JSONPath selected and how
 * many survived. That answer used to cost a detonation.
 */
export default function RestSandboxEditor({
  entries,
  values,
  pending,
  errors,
  onChange,
  onUnstage,
  onReset,
}: {
  entries: CatalogEntry[];
  values: Record<string, SettingValue>;
  pending: Record<string, unknown>;
  errors: Record<string, string>;
  onChange: (key: string, value: unknown) => void;
  onUnstage: (key: string) => void;
  onReset: (key: string) => void;
}) {
  const [sample, setSample] = useState("");
  const [preview, setPreview] = useState<MappingPreview | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);

  const mappingEntries = useMemo(
    () => entries.filter((e) => e.key.startsWith(MAPPING_PREFIX)),
    [entries]
  );
  const plain = useMemo(
    () =>
      entries.filter(
        (e) => !e.key.startsWith(MAPPING_PREFIX) && !SECTIONS.some((s) => e.key.startsWith(s.prefix))
      ),
    [entries]
  );

  const effective = (key: string): unknown =>
    key in pending ? pending[key] : values[key]?.value;

  const runPreview = async () => {
    setRunning(true);
    setPreviewError(null);
    try {
      const parsed = JSON.parse(sample);
      const mapping: Record<string, string> = {};
      for (const e of mappingEntries) {
        const name = e.key.slice(MAPPING_PREFIX.length);
        const value = effective(e.key);
        if (typeof value === "string" && value) mapping[name] = value;
      }
      setPreview(await api.previewSandboxMapping(parsed, mapping));
    } catch (e) {
      setPreview(null);
      setPreviewError(
        e instanceof SyntaxError ? "the pasted text is not valid JSON" : getErrorMessage(e)
      );
    } finally {
      setRunning(false);
    }
  };

  const row = (entry: CatalogEntry) => (
    <FieldRow
      key={entry.key}
      entry={entry}
      current={values[entry.key]}
      staged={pending[entry.key]}
      error={errors[entry.key]}
      onChange={(v) => onChange(entry.key, v)}
      onUnstage={() => onUnstage(entry.key)}
      onReset={() => onReset(entry.key)}
    />
  );

  return (
    <div data-testid="rest-sandbox-editor">
      {plain.map(row)}
      {SECTIONS.map((section) => {
        const rows = entries.filter((e) => e.key.startsWith(section.prefix));
        if (rows.length === 0) return null;
        return (
          <fieldset key={section.prefix} className="mt-4">
            <legend className="text-xs font-medium text-text-primary uppercase tracking-wider">
              {section.title}
            </legend>
            {rows.map(row)}
          </fieldset>
        );
      })}

      {mappingEntries.length > 0 && (
        <fieldset className="mt-4">
          <legend className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Report mapping
          </legend>
          <table className="w-full text-xs mt-2">
            <thead>
              <tr className="border-b border-border text-text-muted">
                <th className="text-left font-normal py-1">Channel</th>
                <th className="text-left font-normal py-1">JSONPath</th>
                <th className="text-left font-normal py-1 w-40">Matched / kept / dropped</th>
              </tr>
            </thead>
            <tbody>
              {mappingEntries.map((entry) => {
                const name = entry.key.slice(MAPPING_PREFIX.length);
                const stats = preview?.channels[name];
                return (
                  <tr key={entry.key} className="border-b border-border align-top">
                    <td className="py-1 text-text-secondary">{name}</td>
                    <td className="py-1">
                      <input
                        className="w-full bg-bg-deep border border-border rounded px-2 py-1 font-mono text-text-primary"
                        aria-label={entry.title}
                        value={String(effective(entry.key) ?? "")}
                        onChange={(e) => onChange(entry.key, e.target.value)}
                      />
                    </td>
                    <td className="py-1 text-text-muted" data-channel={name}>
                      {stats
                        ? stats.error
                          ? stats.error
                          : `${stats.matched} / ${stats.kept} / ${stats.dropped}`
                        : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          <label htmlFor="rest-sample" className="block text-xs text-text-muted mt-3">
            Paste a sample response
          </label>
          <textarea
            id="rest-sample"
            rows={5}
            className="w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-xs font-mono text-text-primary"
            value={sample}
            onChange={(e) => setSample(e.target.value)}
          />
          <div className="flex items-center gap-3 mt-2">
            <button
              type="button"
              className="text-xs text-accent-strong disabled:opacity-50"
              disabled={running || sample.trim() === ""}
              onClick={() => void runPreview()}
            >
              Preview mapping
            </button>
            {preview && (
              <span className="text-[11px] text-text-secondary" role="status">
                sample hash: {preview.target_sha256 || "not matched"}
              </span>
            )}
            {previewError && (
              <span className="text-[11px] text-status-red" role="alert">
                {previewError}
              </span>
            )}
          </div>
        </fieldset>
      )}
    </div>
  );
}
