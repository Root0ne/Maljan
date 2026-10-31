import type { Basis } from "./overview";

/**
 * The one marker for how a claim is known, wherever a claim appears: a
 * filled dot for seen when the sample ran, a ring for not seen (code, rule,
 * file), half of each for partly seen, a dashed ring where the report states
 * no basis. The shape carries the reading as well as the word, so it holds
 * without colour; `detail` is the full sentence, given as the description.
 */
const GLYPH: Record<Basis, string> = {
  seen: "bg-status-blue border-status-blue",
  partly: "border-status-blue bg-transparent",
  "not-seen": "border-text-muted bg-transparent",
  unstated: "border-dashed border-text-muted bg-transparent",
};

export function BasisGlyph({ basis }: { basis: Basis }) {
  return (
    <span aria-hidden="true" className={`relative inline-block h-2 w-2 shrink-0 overflow-hidden rounded-full border ${GLYPH[basis]}`}>
      {basis === "partly" && <span className="absolute inset-y-0 left-0 w-1/2 bg-status-blue" />}
    </span>
  );
}

export default function BasisMark({
  basis,
  label,
  detail,
}: {
  basis: Basis;
  label: string;
  detail?: string;
}) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs text-text-secondary" title={detail}>
      <BasisGlyph basis={basis} />
      {label}
    </span>
  );
}
