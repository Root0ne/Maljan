import Link from "next/link";

/**
 * One number above a table: how many of a thing the analysis found.
 *
 * A zero is not drawn as "0" in large type: it is greyed and says "Not
 * found", so a row of tiles reads as which kinds of evidence exist at a
 * glance. A count nobody measured (`null`) says "Not measured" instead,
 * because "none were found" and "nobody looked" are different answers.
 */
export type KpiState = "found" | "not-found" | "not-measured";

export function kpiState(value: number | null | undefined): KpiState {
  if (value == null) return "not-measured";
  return value > 0 ? "found" : "not-found";
}

const STATE_TEXT: Record<Exclude<KpiState, "found">, string> = {
  "not-found": "Not found",
  "not-measured": "Not measured",
};

export default function KpiTile({
  label,
  value,
  href,
}: {
  label: string;
  value: number | null | undefined;
  /** Where the full list is; the tile becomes a link when given. */
  href?: string;
}) {
  const state = kpiState(value);
  const body = (
    <>
      {state === "found" ? (
        <span className="text-2xl font-semibold leading-8 text-text-primary">
          {(value as number).toLocaleString("en-US")}
        </span>
      ) : (
        <span className="inline-flex h-8 items-center">
          <span className="rounded border border-border px-1.5 text-[11px] leading-4 text-text-muted">
            {STATE_TEXT[state]}
          </span>
        </span>
      )}
      <span className={`text-xs ${state === "found" ? "text-text-secondary" : "text-text-muted"}`}>
        {label}
      </span>
    </>
  );
  const cls = `flex min-w-0 flex-col gap-0.5 rounded-md border border-border px-3 py-2 ${
    state === "found" ? "bg-bg-surface" : "bg-bg-deep"
  }`;
  return href && state === "found" ? (
    <Link href={href} data-kpi={state} className={`${cls} hover:border-text-muted`}>
      {body}
    </Link>
  ) : (
    <div data-kpi={state} className={cls}>
      {body}
    </div>
  );
}
