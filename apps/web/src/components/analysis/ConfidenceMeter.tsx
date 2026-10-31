import { CONFIDENCE_WHY, type VerdictConfidence } from "./overview";

/**
 * The verdict's confidence as five steps, the rung's word and the number
 * beside them: "Moderate-to-high confidence, 85%". The rungs are the
 * report's own (`confidenceRung`), the same five a reader meets as a
 * severity's "High 4/5".
 *
 * The steps are one neutral colour: confidence is how sure the analysis is,
 * not how dangerous the sample is, so a benign verdict held firmly is not a
 * red meter. A confidence nobody assessed draws five empty steps and says
 * so, never a zero. The whole reading ("Malicious, confidence 85 percent")
 * is the image's name; `compact` drops the word and keeps the name.
 */
export default function ConfidenceMeter({
  confidence,
  compact = false,
  title = CONFIDENCE_WHY,
}: {
  confidence: VerdictConfidence;
  compact?: boolean;
  /** What the confidence is about; the verdict's by default. */
  title?: string;
}) {
  return (
    <span role="img" aria-label={confidence.label} title={title} className="inline-flex items-center gap-2">
      <span aria-hidden="true" className="flex items-center gap-[3px]">
        {[1, 2, 3, 4, 5].map((i) => (
          <span
            key={i}
            className={`${compact ? "h-3 w-1" : "h-3.5 w-1.5"} rounded-[1px] ${
              i <= confidence.step ? "bg-text-secondary" : "bg-border"
            }`}
          />
        ))}
      </span>
      {!compact && (
        <span aria-hidden="true" className="text-sm text-text-secondary">
          {confidence.word}
          {confidence.percent !== null && <span className="tabular-nums">, {confidence.percent}%</span>}
        </span>
      )}
    </span>
  );
}
