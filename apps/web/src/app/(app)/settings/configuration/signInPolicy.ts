import type { CatalogEntry } from "@/types/settings";

/** The keys among `keys` whose change the API saves only with the admin's
 *  current password beside it (`needs_current_password`: the sign-in
 *  policy). Read from the served catalogue, never a list kept here. */
export function keysNeedingPassword(
  keys: Iterable<string>,
  entriesByKey: Record<string, CatalogEntry | undefined>
): string[] {
  return [...keys].filter((key) => entriesByKey[key]?.needs_current_password === true).sort();
}

/** The API's own sentence when a save or a reset of the sign-in policy came
 *  without the current password (a 422 naming `current_password`), else null. */
export function passwordRefusal(errors: Record<string, string>): string | null {
  return errors.current_password ?? null;
}
