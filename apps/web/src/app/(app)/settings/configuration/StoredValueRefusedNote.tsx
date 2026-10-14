"use client";

import type { SettingsSchema } from "@/types/settings";
import { useOptionalSettingsContext } from "./SettingsContext";

/** What the console says beside a stored value the API reads past, or `""`.
 *
 *  The API serves each stored value the settings model refuses
 *  (`SchemaResponse.stored_values_refused`): it is not in force, its default
 *  is, until it is saved again or reset. Saying so beside the row is what
 *  keeps a read past it from being silent. */
export function refusedNote(schema: SettingsSchema | null | undefined, key: string): string {
  const reason = schema?.stored_values_refused?.[key];
  if (reason === undefined) return "";
  const why = typeof reason === "string" && reason ? `: ${reason}` : "";
  return (
    `The stored value is not in force${why}. Its default is used until a value is saved ` +
    "here again or the stored one is reset."
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
