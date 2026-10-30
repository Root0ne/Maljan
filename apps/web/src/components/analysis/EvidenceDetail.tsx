import Link from "next/link";
import { SeverityPill, Tag } from "@/components/ui/Pill";
import type { SeverityRating } from "@/types/malware-report";
import { VOICE_TEXT, type Voice } from "./overview";

/**
 * What the evidence drawer shows for one finding: what it is, how it is
 * known, the concrete lines behind it, and the stored records it rests on,
 * each a link into the full evidence view.
 */
export interface EvidenceSubject {
  title: string;
  severity?: SeverityRating | null;
  category?: string;
  voice?: Voice;
  details: string[];
  techniques: string[];
  evidenceIds: string[];
}

export default function EvidenceDetail({ jobId, subject }: { jobId: string; subject: EvidenceSubject }) {
  return (
    <div className="space-y-5 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        {subject.severity !== undefined && <SeverityPill severity={subject.severity} />}
        {subject.category && <Tag>{subject.category}</Tag>}
        {subject.techniques.map((t) => (
          <Tag key={t}>{t}</Tag>
        ))}
      </div>
      {subject.voice && <p className="text-text-secondary">{VOICE_TEXT[subject.voice]}.</p>}

      <div>
        <h3 className="mb-1.5 text-xs font-semibold text-text-secondary">What was seen</h3>
        {subject.details.length > 0 ? (
          <ul className="space-y-1.5">
            {subject.details.map((d) => (
              <li key={d} className="break-words rounded border border-border-light bg-bg-deep px-2 py-1 font-mono text-xs text-text-primary">
                {d}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-text-muted">No concrete lines were recorded for this finding.</p>
        )}
      </div>

      <div>
        <h3 className="mb-1.5 text-xs font-semibold text-text-secondary">Records behind it</h3>
        {subject.evidenceIds.length > 0 ? (
          <ol className="space-y-1">
            {subject.evidenceIds.map((id, i) => (
              <li key={id}>
                <Link
                  href={`/analysis/${encodeURIComponent(jobId)}/evidence?evidence=${encodeURIComponent(id)}`}
                  className="inline-flex items-center gap-1 text-accent-strong hover:underline"
                >
                  Record {i + 1}
                  <span className="font-mono text-[11px] text-text-muted">{id}</span>
                </Link>
              </li>
            ))}
          </ol>
        ) : (
          <p className="text-text-muted">No individual records are linked to this finding.</p>
        )}
      </div>
    </div>
  );
}
