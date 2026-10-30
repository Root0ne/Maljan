import { verdictTone } from "@/lib/verdict";
import type { VerdictConfidence } from "./overview";

/**
 * The verdict's confidence as a ring, filled in the verdict's colour, with
 * the word "Confidence" beside it so the number is never read as a score.
 *
 * A confidence nobody assessed draws an empty ring and a dash, never a zero.
 * The whole reading ("Malicious, confidence 91 percent") is the image's name.
 * The small size, for the folded header, drops the word and keeps the name.
 */
const R = 19;
const C = 2 * Math.PI * R;

/** How much of the ring's stroke is drawn for `percent`. */
export function gaugeDash(percent: number | null): string {
  const filled = percent === null ? 0 : (Math.min(100, Math.max(0, percent)) / 100) * C;
  return `${filled.toFixed(2)} ${C.toFixed(2)}`;
}

export default function ConfidenceGauge({
  confidence,
  verdict,
  size = "md",
}: {
  confidence: VerdictConfidence;
  verdict: string | null | undefined;
  size?: "sm" | "md";
}) {
  const tone = verdictTone(verdict);
  const box = size === "sm" ? "h-8 w-8" : "h-12 w-12";
  return (
    <div role="img" aria-label={confidence.label} className="flex shrink-0 items-center gap-2">
      <div className={`relative ${box}`} aria-hidden="true">
        <svg viewBox="0 0 48 48" className={`${box} -rotate-90`}>
          <circle cx="24" cy="24" r={R} fill="none" stroke="var(--border)" strokeWidth="5" />
          <circle
            cx="24"
            cy="24"
            r={R}
            fill="none"
            stroke={tone.fill}
            strokeWidth="5"
            strokeDasharray={gaugeDash(confidence.percent)}
            strokeLinecap="butt"
          />
        </svg>
        <span
          className={`absolute inset-0 flex items-center justify-center font-semibold text-text-primary ${
            size === "sm" ? "text-[10px]" : "text-xs"
          }`}
        >
          {confidence.percent === null ? "–" : `${confidence.percent}%`}
        </span>
      </div>
      {size === "md" && (
        <span aria-hidden="true" className="text-xs leading-4 text-text-secondary">
          Confidence
        </span>
      )}
    </div>
  );
}
