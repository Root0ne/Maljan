/**
 * Turns a parsed export document into what `ImportDialog` shows before it
 * sends anything: a `describeChange` line per known, editable key whose
 * imported value differs from what is in effect now, and an error per key
 * the import cannot apply at all. Pure and side-effect free — no React, no
 * network — so the four ways a document can fail (an unknown key, a
 * read-only key, an unsupported `format`, a key that imports unchanged) are
 * unit-tested directly.
 */
import type { CatalogEntry } from "@/types/settings";
import { describeChange, type ChangeLine } from "./describeChange";
import { SETTINGS_EXPORT_FORMAT } from "@/types/settings";

/** The shape of a parsed `.json` export file, before it is known to be valid. */
export interface ImportDoc {
  format: string;
  values: Record<string, unknown>;
}

export interface ImportPreview {
  lines: ChangeLine[];
  errors: Record<string, string>;
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || a === undefined || b === null || b === undefined) return a === b;
  if (typeof a !== "object" || typeof b !== "object") return false;
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * `entriesByKey` is the whole catalog, keyed by dotted key — the same map
 * `SettingsContextValue.entriesByKey` already carries. `currentValues` is
 * the *effective* value (staged wins over stored) of every key the document
 * mentions, keyed the same way; a key the document names that has no entry
 * here reads as `undefined`, same as "unset".
 *
 * A secret always gets a line when it is present in the document: the API
 * never echoes a secret's value back (`SettingValue.value` is always `null`
 * for one), so there is no "unchanged" a secret could compare equal to —
 * the file's value is shown as `(secret) will be set`, never the value
 * itself, and counted as a change every time.
 */
export function buildImportPreview(
  doc: ImportDoc,
  entriesByKey: Record<string, CatalogEntry>,
  currentValues: Record<string, unknown>
): ImportPreview {
  if (doc.format !== SETTINGS_EXPORT_FORMAT) {
    return { lines: [], errors: { format: "unsupported format" } };
  }

  const lines: ChangeLine[] = [];
  const errors: Record<string, string> = {};

  for (const [key, importedValue] of Object.entries(doc.values)) {
    const entry = entriesByKey[key];
    if (!entry) {
      errors[key] = "unknown key";
      continue;
    }
    if (!entry.editable) {
      errors[key] = "read-only";
      continue;
    }
    if (entry.secret) {
      lines.push({
        key,
        title: entry.title,
        summary: "(secret) will be set",
        applies: entry.applies,
      });
      continue;
    }
    const current = currentValues[key];
    if (deepEqual(current, importedValue)) continue;
    lines.push(describeChange(entry, current, importedValue));
  }

  return { lines, errors };
}
