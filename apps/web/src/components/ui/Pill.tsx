import { ladderDots, severityTone, severityWord, NEUTRAL_TONE } from "@/lib/severity";
import { verdictLabel, verdictTone } from "@/lib/verdict";

/**
 * The two small labels every surface shares: a severity on one n/5 scale and
 * a verdict in its colour.
 *
 * One scale everywhere: the ladder's five rungs (`lib/severity`) read as
 * 1/5 for Informational up to 5/5 for Critical, with five ticks filled to the
 * rung, so a reader compares two rows by length as well as by word. The word
 * and the number are always printed; the colour never carries the reading
 * alone. A severity that is not a rung is "Unrated", in the neutral tone,
 * never a guessed colour.
 */

/** "High 4/5" — or "Unrated" for a word off the ladder. */
export function severityPillText(label: string | null | undefined): string {
  const n = ladderDots(label);
  return n === 0 ? "Unrated" : `${severityWord(label)} ${n}/5`;
}

export function SeverityPill({ severity }: { severity: string | null | undefined }) {
  const n = ladderDots(severity);
  const tone = n === 0 ? NEUTRAL_TONE : severityTone(severity);
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-1.5 py-px text-[11px] font-medium leading-4 ${tone.text} ${tone.bg} ${tone.border}`}
    >
      <span aria-hidden="true" className="flex items-center gap-px">
        {[1, 2, 3, 4, 5].map((i) => (
          <span
            key={i}
            className={`h-2.5 w-1 rounded-sm ${i <= n ? tone.dot : "bg-border"}`}
          />
        ))}
      </span>
      <span>{severityPillText(severity)}</span>
    </span>
  );
}

export function VerdictPill({ verdict }: { verdict: string | null | undefined }) {
  const tone = verdictTone(verdict);
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-px text-[11px] font-semibold leading-4 ${tone.text} ${tone.border}`}
    >
      {verdictLabel(verdict)}
    </span>
  );
}

/** A plain tag: a classification, a priority, a type. */
export function Tag({ children, title }: { children: React.ReactNode; title?: string }) {
  return (
    <span
      title={title}
      className="inline-flex items-center rounded border border-border bg-bg-elevated px-1.5 py-px text-[11px] leading-4 text-text-secondary"
    >
      {children}
    </span>
  );
}
