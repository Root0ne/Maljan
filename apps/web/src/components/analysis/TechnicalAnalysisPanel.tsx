"use client";

import EvidenceChips from "./EvidenceChips";
import {
  REPORT_MODEL_VOICE,
  c2Channels,
  channelEvidence,
  commands,
  configFindings,
  configuration,
  defangEndpoint,
  executionFlow,
  flowMark,
  flowNote,
  hasTechnicalAnalysis,
  hostIdentifiers,
  identifierFindings,
} from "./reportProse";
import type { MalwareReport } from "@/types/malware-report";

/**
 * The report model's technical analysis: the execution flow, the
 * configuration it recovered, the host identifiers it read, the commands the
 * sample accepts and its C2 channels — the exported report's §4, §5.3, the
 * model's table in §9, §5.6 and §5.7, in that order.
 *
 * Every block is labelled with its voice. The words are the report model's and
 * are printed as written; a step's mark (observed or assessed) is the model's
 * own; a row that cites nothing says so. The platform's unresolved finding on
 * a step or a configuration item is printed beside it, as the exported report
 * prints it, and a channel's endpoints are defanged as they are there.
 */
export default function TechnicalAnalysisPanel({ report }: { report: MalwareReport }) {
  if (!hasTechnicalAnalysis(report)) return null;
  const steps = executionFlow(report);
  const config = configuration(report);
  const cmds = commands(report);
  const channels = c2Channels(report);
  const uncitedConfig = configFindings(report);
  const identifiers = hostIdentifiers(report);
  const uncitedIdentifiers = identifierFindings(report);

  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border flex items-baseline gap-3">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          Technical analysis
        </h2>
        <span className="text-[11px] italic text-text-muted">{REPORT_MODEL_VOICE}</span>
      </div>
      <div className="p-4 space-y-5">
        {steps.length > 0 && (
          <section>
            <h3 className="text-[11px] uppercase tracking-wider text-text-muted mb-1.5">
              Execution flow
            </h3>
            <ol className="space-y-1.5">
              {steps.map((step, i) => (
                <li key={`${step.order}-${i}`} className="text-sm text-text-secondary">
                  <span className="text-text-muted mr-2 font-mono">{i + 1}.</span>
                  {step.action}
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

        {config.length > 0 && (
          <section>
            <h3 className="text-[11px] uppercase tracking-wider text-text-muted mb-1.5">
              Configuration
            </h3>
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-text-muted">
                  <th className="py-1 pr-3 font-medium">Key</th>
                  <th className="py-1 pr-3 font-medium">Value</th>
                  <th className="py-1 pr-3 font-medium">How obtained</th>
                  <th className="py-1 font-medium">Evidence</th>
                </tr>
              </thead>
              <tbody>
                {config.map((item, i) => (
                  <tr key={`${item.key}-${i}`} className="border-t border-border align-top">
                    <td className="py-1 pr-3 text-text-primary">{item.key}</td>
                    <td className="py-1 pr-3 font-mono break-all text-text-secondary">
                      {item.value}
                    </td>
                    <td className="py-1 pr-3 text-text-muted">
                      {item.how_obtained}
                      <Unresolved
                        note={
                          uncitedConfig.has(i + 1) ? "unresolved: report.configuration_uncited" : ""
                        }
                      />
                    </td>
                    <td className="py-1">
                      <Cited ids={item.evidence_refs} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        )}

        {identifiers.length > 0 && (
          <section>
            <h3 className="text-[11px] uppercase tracking-wider text-text-muted mb-1.5">
              Host identifiers
            </h3>
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
                    <td className="py-1 pr-3 text-text-muted">{item.purpose || "-"}</td>
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
            <p className="mt-1 text-[10px] italic text-text-muted">
              Read out of this run&apos;s evidence by the report model; not published.
            </p>
          </section>
        )}

        {cmds.length > 0 && (
          <section>
            <h3 className="text-[11px] uppercase tracking-wider text-text-muted mb-1.5">
              Commands
            </h3>
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
                    <td className="py-1 pr-3 font-mono text-text-primary">{cmd.name}</td>
                    <td className="py-1 pr-3 text-text-secondary">{cmd.description || "-"}</td>
                    <td className="py-1">
                      <Cited ids={cmd.evidence_refs} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        )}

        {channels.length > 0 && (
          <section>
            <h3 className="text-[11px] uppercase tracking-wider text-text-muted mb-1.5">
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
