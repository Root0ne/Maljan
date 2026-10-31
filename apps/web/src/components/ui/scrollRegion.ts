/**
 * Props for the box a table scrolls sideways in: a focusable region with its
 * own name, so a keyboard reader can reach the part that is off screen and a
 * screen reader hears which table it is (landmark names must be unique on a
 * page, so the name is the table's own title, never a shared phrase).
 */
export function scrollRegion(name: string) {
  return {
    role: "region" as const,
    tabIndex: 0,
    "aria-label": `${name} table, scrolls sideways`,
  };
}

/** The focus ring every scroll region carries. */
export const SCROLL_REGION_FOCUS =
  "focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent";
