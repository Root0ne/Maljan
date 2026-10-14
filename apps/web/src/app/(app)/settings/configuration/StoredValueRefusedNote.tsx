"use client";

import type { SettingsSchema } from "@/types/settings";
import { useOptionalSettingsContext } from "./SettingsContext";

/** What the console says beside a refused stored value, or `""`.
 *
 *  The API serves each stored value the settings model refuses
 *  (`SchemaResponse.stored_values_refused`). Only this page reads past it, so
 *  the admin can repair it; everything that runs fails until then. */
export function refusedNote(schema: SettingsSchema | null | undefined, key: string): string {
  const reason = schema?.stored_values_refused?.[key];
  if (reason === undefined) return "";
  const why = typeof reason === "string" && reason ? `: ${reason}` : "";
  return (
    `The stored value is refused${why}. Analyses and the routes that read the settings ` +
    "fail until a value is saved here again or the stored one is reset; this page shows " +
    "the default meanwhile."
  );
}

export default function StoredValueRefusedNote({ settingKey }: { settingKey: string }) {
  const schema = useOptionalSettingsContext()?.schema;
  const text = refusedNote(schema, settingKey);
  if (!text) return null;
  return (
    <p role="alert" className="mt-1 text-[11px] text-status-orange" data-stored-value-refused>
      {text}
    </p>
  );
}
