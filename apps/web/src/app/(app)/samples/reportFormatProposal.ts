/** A proposed report format declaration, as an unread upload's answer carries it.
 *
 *  The API reads the proposal from the report's shape (`maljan.core.report_proposals`):
 *  each field with its value, where in the report it was read and how sure the
 *  reading is, and the whole as one declaration. Nothing here applies anything:
 *  an admin reads, edits and accepts the declaration, and the API decides
 *  whether it recognises the report before saving it. */

export interface ProposedFormatField {
  value: unknown;
  evidence: string[];
  confidence: string;
  requires?: string[];
}

export interface ReportFormatProposal {
  v: number;
  fields: Record<string, ProposedFormatField>;
  declaration?: Record<string, unknown>;
  failed?: string;
  /** What the proposer's reading horizons left unread, in words. */
  notes?: string[];
}

const CONFIDENCES = new Set(["high", "medium", "low"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The proposal as the console shows it; a part of an odd shape is dropped. */
export function readProposal(raw: unknown): ReportFormatProposal | null {
  if (!isRecord(raw) || typeof raw.v !== "number" || !isRecord(raw.fields)) return null;
  const fields: Record<string, ProposedFormatField> = {};
  for (const [name, held] of Object.entries(raw.fields)) {
    if (!isRecord(held)) continue;
    const evidence = Array.isArray(held.evidence)
      ? held.evidence.filter((e): e is string => typeof e === "string")
      : [];
    if (typeof held.confidence !== "string" || !CONFIDENCES.has(held.confidence)) continue;
    fields[name] = {
      value: held.value,
      evidence,
      confidence: held.confidence,
      ...(Array.isArray(held.requires)
        ? { requires: held.requires.filter((r): r is string => typeof r === "string") }
        : {}),
    };
  }
  return {
    v: raw.v,
    fields,
    ...(isRecord(raw.declaration) ? { declaration: raw.declaration } : {}),
    ...(typeof raw.failed === "string" ? { failed: raw.failed } : {}),
    ...(Array.isArray(raw.notes)
      ? { notes: raw.notes.filter((n): n is string => typeof n === "string") }
      : {}),
  };
}

/** Whether a report row was accepted unread, so its proposal can be read again. */
export function isUnread(format: string | null | undefined): boolean {
  return format === "unread";
}

/** The fields in the order they are shown: how it is recognised, then where its parts sit. */
export function shownFields(proposal: ReportFormatProposal): [string, ProposedFormatField][] {
  const rank = (name: string) =>
    name === "detect" ? 0 : name === "reader" ? 1 : name.startsWith("mapping.") ? 3 : 2;
  return Object.entries(proposal.fields).sort(
    ([a], [b]) => rank(a) - rank(b) || a.localeCompare(b)
  );
}

/** A field's value as one line of text. */
export function showValue(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

/** The declaration an admin edited, read back: an object, or the reason it is not one. */
export function parseDeclaration(
  text: string
): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, error: "The declaration is not valid JSON." };
  }
  if (!isRecord(parsed)) return { ok: false, error: "The declaration must be a JSON object." };
  if (typeof parsed.name !== "string" || !parsed.name) {
    return { ok: false, error: "The declaration needs a name." };
  }
  return { ok: true, value: parsed };
}
