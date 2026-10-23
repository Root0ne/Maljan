import { ROWS_PER_STEP, nextStep } from "@/lib/pagedRows";

/** The footer of a table drawn a step at a time (`lib/pagedRows`). */
export default function ShowMoreRows({
  shown,
  total,
  onShow,
}: {
  shown: number;
  total: number;
  onShow: (count: number) => void;
}) {
  if (shown >= total) return null;
  const next = nextStep(shown, total);
  return (
    <div className="px-4 py-2 text-[11px] text-text-muted border-t border-border flex flex-wrap items-center gap-3">
      <span>
        Showing {shown.toLocaleString("en-US")} of {total.toLocaleString("en-US")}.
      </span>
      <button
        type="button"
        className="text-accent-strong hover:underline"
        onClick={() => onShow(next)}
      >
        Show {Math.min(ROWS_PER_STEP, total - shown).toLocaleString("en-US")} more
      </button>
      <button type="button" className="text-accent-strong hover:underline" onClick={() => onShow(total)}>
        Show all
      </button>
    </div>
  );
}
