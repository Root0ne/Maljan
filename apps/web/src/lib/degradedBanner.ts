/**
 * What the degraded-run banner may say about the confidence beside it.
 *
 * It said one thing: "The confidence shown above is the judge's own, set
 * knowing the reasons below." That is true of a run whose judge stated a
 * verdict and put a number on it, and false of every other reading — on the
 * unrecognised path the whole point is that the number is *not* the judge's,
 * and the banner was the console's main explanation of the inconclusive
 * verdict while asserting the opposite of it.
 *
 * Four readings, four sentences, and one for a report stored before the
 * reading existed, which can only be read off whether a confidence is there.
 */

import type { VerdictReading } from "@/lib/api";

const OPENING =
  "The pipeline produced only partial signal, so the verdict and severity " +
  "should be treated as preliminary.";

const ABOUT_THE_CONFIDENCE: Record<VerdictReading, string> = {
  stated: "The confidence shown above is the judge's own, set knowing the reasons below.",
  unrecognised:
    "The judge's answer could not be read as a verdict, so the verdict above is not " +
    "the judge's and no confidence is published for it.",
  unstated:
    "The judge stated no verdict, so the verdict above was read from the objects in " +
    "its bundle and no confidence is published for it.",
  fallback:
    "The judge did not answer with a bundle, so the verdict above was not one it " +
    "expressed and no confidence is published for it.",
};

/**
 * The banner's paragraph, for a run with this reading and this confidence.
 *
 * With no reading — every report stored before the field — the confidence is
 * all there is to go on: a number is the judge's, and its absence is said as
 * the absence it is rather than explained by a cause nobody recorded.
 */
export function degradedBannerText(
  reading: VerdictReading | null | undefined,
  confidence: number | null | undefined,
): string {
  if (reading) return `${OPENING} ${ABOUT_THE_CONFIDENCE[reading]}`;
  if (confidence === null || confidence === undefined) {
    return `${OPENING} No confidence was assessed for this verdict.`;
  }
  return `${OPENING} ${ABOUT_THE_CONFIDENCE.stated}`;
}
