"use client";

import Link from "next/link";

import { scrollRegion, SCROLL_REGION_FOCUS } from "@/components/ui/scrollRegion";
import { useReport } from "./AnalysisContext";
import CitedProse from "./CitedProse";
import EvidenceChips from "./EvidenceChips";
import {
  REPORT_MODEL_VOICE,
  c2Channels,
  channelEvidence,
  commands,
  configuration,
  defangEndpoint,
  executionFlow,
  flowMark,
  flowNote,
  hasTechnicalAnalysis,
  hostIdentifiers,
  identifierFindings,
  technicalSubsections,
} from "./reportProse";
import type { MalwareReport } from "@/types/malware-report";

/**
 * The report model's technical analysis: the execution flow, the host
 * identifiers it read, the commands the sample accepts and its C2 channels —
 * the exported report's §4, the model's table in §9, §5.6 and §5.7, in that
 * order. The configuration it recovered (§5.3) is drawn once, under Static &
 * code, and this panel links there.
 *
 * Every block is labelled with its voice. The words are the report model's and
 * are printed as written; a step's mark (observed or assessed) is the model's
 * own; a row that cites nothing says so. The platform's unresolved finding on
 * a step is printed beside it, as the exported report prints it, and a
 * channel's endpoints are defanged as they are there.
 */
export default function TechnicalAnalysisPanel({ report }: { report: MalwareReport }) {
  const { jobId } = useReport();
  if (!hasTechnicalAnalysis(report)) return null;
  const steps = executionFlow(report);
  const config = configuration(report);
  const cmds = commands(report);
  const channels = c2Channels(report);
  const identifiers = hostIdentifiers(report);
  const uncitedIdentifiers = identifierFindings(report);
  const blocks = technicalSubsections(report);

  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border flex items-baseline gap-3">
        <h2 className="text-sm font-semibold text-text-primary">
          Technical analysis
        </h2>
        <span className="text-[11px] italic text-text-muted">{REPORT_MODEL_VOICE}</span>
      </div>
      <div className="p-4 space-y-5">
        {steps.length > 0 && (
          <section>
            <h3 className="text-xs text-text-muted mb-1.5">
              Execution flow
            </h3>
            <ol className="space-y-1.5">
              {steps.map((step, i) => (
                <li key={`${step.order}-${i}`} className="text-sm text-text-secondary">
                  <span className="text-text-muted mr-2 font-mono">{i + 1}.</span>
                  <span className="break-words [overflow-wrap:anywhere]">
                    <CitedProse text={step.action} />
                  </span>
                  <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded bg-bg-active text-text-muted">
                    {flowMark(step)}
                  </span>
                  <Cited ids={step.evidence_refs} />
                  <Unresolved note={flowNote(report, step)} />
                </li>
              ))}
            </ol>
          </section>
        )}

        {/* Each fact once: the configuration's table is Static & code's, where
            each value has a copy; this says where it is. */}
        {config.length > 0 && (
          <p className="text-xs text-text-secondary">
            Configuration: see{" "}
            <Link href={`/analysis/${jobId}/static#decoded`} className="text-accent-strong underline hover:no-underline">
              Static &amp; code › Decoded strings and configuration
            </Link>
          </p>
        )}

        {identifiers.length > 0 && (
          <section>
            <h3 className="text-xs text-text-muted mb-1.5">
              Host identifiers
            </h3>
            <div {...scrollRegion("Host identifiers")} className={`max-w-full overflow-x-auto ${SCROLL_REGION_FOCUS}`}>
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-text-muted">
                  <th className="py-1 pr-3 font-medium">Kind</th>
                  <th className="py-1 pr-3 font-medium">Value</th>
                  <th className="py-1 pr-3 font-medium">Purpose</th>
                  <th className="py-1 font-medium">Evidence</th>
                </tr>
              </thead>
              <tbody>
                {identifiers.map((item, i) => (
                  <tr key={`${item.value}-${i}`} className="border-t border-border align-top">
                    <td className="py-1 pr-3 text-text-primary">{item.kind}</td>
                    <td className="py-1 pr-3 font-mono break-all text-text-secondary">
                      {item.value}
                    </td>
                    <td className="py-1 pr-3 break-words text-text-muted [overflow-wrap:anywhere]">{item.purpose?.trim() ? <CitedProse text={item.purpose.trim()} /> : "not stated"}</td>
                    <td className="py-1">
                      <Cited ids={item.evidence_refs} />
                      <Unresolved
                        note={
                          uncitedIdentifiers.has(i + 1)
                            ? "unresolved: report.identifier_uncited"
                            : ""
                        }
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
            <p className="mt-1 text-[10px] italic text-text-muted">
              Read out of this run&apos;s evidence by the AI that wrote the report. This table publishes
              nothing itself: a value it lists is published only where the IOC table publishes
              it.
            </p>
          </section>
        )}

        {cmds.length > 0 && (
          <section>
            <h3 className="text-xs text-text-muted mb-1.5">
              Commands
            </h3>
            <div {...scrollRegion("Commands")} className={`max-w-full overflow-x-auto ${SCROLL_REGION_FOCUS}`}>
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-text-muted">
                  <th className="py-1 pr-3 font-medium">ID</th>
                  <th className="py-1 pr-3 font-medium">Command</th>
                  <th className="py-1 pr-3 font-medium">Description</th>
                  <th className="py-1 font-medium">Evidence</th>
                </tr>
              </thead>
              <tbody>
                {cmds.map((cmd, i) => (
                  <tr key={`${cmd.name}-${i}`} className="border-t border-border align-top">
                    <td className="py-1 pr-3 font-mono text-text-muted">{cmd.id ?? "-"}</td>
                    <td className="py-1 pr-3 font-mono break-all text-text-primary">{cmd.name}</td>
                    <td className="py-1 pr-3 break-words text-text-secondary [overflow-wrap:anywhere]">{cmd.description ? <CitedProse text={cmd.description} /> : "-"}</td>
                    <td className="py-1">
                      <Cited ids={cmd.evidence_refs} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            </div>
          </section>
        )}

        {channels.length > 0 && (
          <section>
            <h3 className="text-xs text-text-muted mb-1.5">
              C2 channels
            </h3>
            <ul className="space-y-2">
              {channels.map((ch, i) => (
                <li key={`${ch.name}-${i}`} className="text-xs text-text-secondary">
                  <span className="text-text-primary font-medium">{ch.name}</span>
                  {ch.protocol && <span className="ml-2 font-mono">{ch.protocol}</span>}
                  {ch.encryption && <span className="ml-2">encryption: {ch.encryption}</span>}
                  {(ch.beacon_format || ch.packet_layout) && (
                    <span className="ml-2">
                      format: {[ch.beacon_format, ch.packet_layout].filter(Boolean).join(" / ")}
                    </span>
                  )}
                  {(ch.endpoints ?? []).length > 0 && (
                    <div className="mt-0.5 font-mono break-all text-text-muted">
                      {(ch.endpoints ?? []).map(defangEndpoint).join(", ")}
                    </div>
                  )}
                  <Cited ids={channelEvidence(ch)} />
                </li>
              ))}
            </ul>
          </section>
        )}

        {/* The rest of the spine: prose subsections, flags, the kill list,
            shadow-copy commands, the encryption scheme and the ransom note. */}
        {blocks.map((block) => (
          <section key={block.key}>
            <h3 className="text-xs text-text-muted mb-1.5">
              {block.title}
            </h3>
            {block.body && (
              <p className="text-sm text-text-secondary whitespace-pre-wrap break-words [overflow-wrap:anywhere]">
                <CitedProse text={block.body} />
              </p>
            )}
            {block.facts.length > 0 && (
              <dl className="mt-1 grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-xs">
                {block.facts.map(([label, value]) => (
                  <div key={label} className="contents">
                    <dt className="text-text-muted">{label}</dt>
                    <dd className="min-w-0 font-mono break-all text-text-secondary"><CitedProse text={value} /></dd>
                  </div>
                ))}
              </dl>
            )}
            {block.items.length > 0 && (
              <ul className="mt-1 space-y-0.5">
                {block.items.map((item, i) => (
                  <li key={`${item}-${i}`} className="text-xs font-mono break-all text-text-secondary">
                    <CitedProse text={item} />
                  </li>
                ))}
              </ul>
            )}
            <Cited ids={block.evidence} />
          </section>
        ))}
      </div>
    </div>
  );
}

/** The platform's note beside a model's row, in the words the exported report prints. */
function Unresolved({ note }: { note: string }) {
  if (!note) return null;
  return <span className="ml-2 text-[10px] italic text-status-orange">({note})</span>;
}

/** A row's citations, or the words the exported report prints when it has none. */
function Cited({ ids }: { ids: string[] | undefined }) {
  if (!ids || ids.length === 0) {
    return <span className="ml-2 text-[10px] italic text-text-muted">no evidence cited</span>;
  }
  return <EvidenceChips ids={ids} className="ml-2" />;
}
