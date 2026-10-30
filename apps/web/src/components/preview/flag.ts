/**
 * Whether the new analysis page is switched on.
 *
 * Off unless the build sets `NEXT_PUBLIC_UI_NEXT` to "true" (or "1"): today's
 * pages are what every reader gets, and the preview answers 404 until an
 * operator opts in. Read at build time, like every NEXT_PUBLIC_ value.
 */
export function previewEnabled(value: string | undefined = process.env.NEXT_PUBLIC_UI_NEXT): boolean {
  const v = (value ?? "").trim().toLowerCase();
  return v === "true" || v === "1";
}
