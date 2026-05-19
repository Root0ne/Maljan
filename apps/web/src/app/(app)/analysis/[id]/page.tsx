"use client";

import { useState } from "react";

import { useReport } from "./layout";
import { api } from "@/lib/api";
import { downloadBlob } from "@/lib/report-utils";
import { SEVERITY_STYLES } from "@/types/malware-report";
import type { MalwareReport, TTPMapping } from "@/types/malware-report";

const VERDICT_COLORS: Record<string, string> = {
  malicious: "bg-status-red",
  suspicious: "bg-status-orange",
  benign: "bg-status-green",
  unknown: "bg-text-muted",
};

const VERDICT_TEXT: Record<string, string> = {
  malicious: "text-status-red",
  suspicious: "text-status-orange",
  benign: "text-status-green",
  unknown: "text-text-muted",
};

function lc(v: string | null | undefined): string {
  return (v || "unknown").toLowerCase();
}

function pct(x: number | null | undefined): number {
  if (!x) return 0;
  return Math.round(x * 100);
}

function countNetworkIOCs(mr: MalwareReport): {
  domains: number;
  ips: number;
  urls: number;
  suspicious: number;
} {
  const n = mr.network;
  if (!n) return { domains: 0, ips: 0, urls: 0, suspicious: 0 };
  const susp =
    n.domains.filter((d) => d.is_suspicious).length +
    n.ips.filter((i) => i.is_suspicious).length;
  return { domains: n.domains.length, ips: n.ips.length, urls: n.urls.length, suspicious: susp };
}

export default function SummaryTab() {
  const { report, job, loading } = useReport();

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  if (!report && (!job || job.status !== "completed")) {
    return (
      <div className="p-4 text-sm text-text-secondary animate-pulse">
        Analysis in progress... Gathering intelligence.
      </div>
    );
  }

  const mr = report?.malware_report ?? null;
  return mr ? <MalwareReportSummary mr={mr} /> : <LegacySummary />;
}

/* ── Legacy summary (pre-Faz5 reports without malware_report payload) ── */
function LegacySummary() {
  const { report } = useReport();
  const agentSummary =
    report?.agent_findings?.map((f) => {
      const p = pct(f.final_confidence);
      let verdict = "unknown";
      if (p >= 80) verdict = "malicious";
      else if (p >= 50) verdict = "suspicious";
      else verdict = "benign";
      return { name: f.agent_name, verdict, confidence: p };
    }) || [];

  let keyFindings: string[] = [];
  if (report?.agent_findings) {
    for (const finding of report.agent_findings) {
      if (finding.claims && Array.isArray(finding.claims)) {
        for (const claim of finding.claims) {
          if (claim && typeof claim === "object" && "description" in claim) {
            keyFindings.push(String((claim as { description: unknown }).description));
          } else if (claim && typeof claim === "object" && "claim" in claim) {
            keyFindings.push(String((claim as { claim: unknown }).claim));
          } else if (typeof claim === "string") {
            keyFindings.push(claim);
          }
        }
      }
    }
  }
  if (keyFindings.length === 0 && report?.mitre_techniques) {
    keyFindings = report.mitre_techniques.map((t) => {
      const tt = t as { name?: string; technique_id?: string };
      return tt.name || tt.technique_id || "Unknown technique";
    });
  }
  keyFindings = Array.from(new Set(keyFindings)).slice(0, 6);
  if (keyFindings.length === 0) {
    keyFindings = ["No specific findings were extracted."];
  }

  const verdictLabel = report?.verdict
    ? report.verdict.charAt(0).toUpperCase() + report.verdict.slice(1)
    : "Unknown";
  const confidence = pct(report?.overall_confidence);
  const verdictColorClass =
    VERDICT_TEXT[lc(report?.verdict)] || VERDICT_TEXT.unknown;

  return (
    <div className="grid grid-cols-2 gap-4">
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Agent Consensus
          </h2>
        </div>
        <div className="p-4 space-y-3">
          {agentSummary.length > 0 ? (
            agentSummary.map((a) => (
              <div key={a.name} className="flex items-center gap-3">
                <span className="text-xs text-text-secondary w-32 shrink-0 truncate">
                  {a.name}
                </span>
                <div className="flex-1 h-2 bg-bg-deep rounded-sm overflow-hidden">
                  <div
                    className={`h-full rounded-sm ${VERDICT_COLORS[a.verdict] || VERDICT_COLORS.unknown}`}
                    style={{ width: `${a.confidence}%`, opacity: 0.7 }}
                  />
                </div>
                <span
                  className={`text-xs font-mono w-8 text-right ${VERDICT_TEXT[a.verdict] || VERDICT_TEXT.unknown}`}
                >
                  {a.confidence}
                </span>
              </div>
            ))
          ) : (
            <div className="text-sm text-text-secondary">No agent data available.</div>
          )}
        </div>
      </div>

      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Key Findings
          </h2>
        </div>
        <div className="p-4">
          <ul className="space-y-2">
            {keyFindings.map((f, i) => (
              <li key={i} className="flex gap-2 text-xs text-text-secondary">
                <span className="text-status-red mt-0.5 shrink-0">-</span>
                <span className="truncate" title={f}>
                  {f}
                </span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="col-span-2 bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Executive Summary
          </h2>
        </div>
        <div className="p-4">
          <p className="text-sm text-text-secondary leading-relaxed">
            The analyzed sample has been classified as{" "}
            <strong className={verdictColorClass}>{verdictLabel}</strong> with a consensus
            confidence score of <strong>{confidence}/100</strong>.
            {report?.malware_category
              ? ` Detected malware category: ${report.malware_category}.`
              : ""}
            {agentSummary.length > 0
              ? ` The analysis involved ${agentSummary.length} agent(s).`
              : ""}
            {!report ? " Analysis is currently incomplete or data is missing." : ""}
          </p>
        </div>
      </div>
    </div>
  );
}

/* ── MalwareReport summary (Faz 5+ payload) ──────────────────────────── */
function MalwareReportSummary({ mr }: { mr: MalwareReport }) {
  const { report } = useReport();
  const reportId = report?.id ?? "";
  const sevStyle = SEVERITY_STYLES[mr.severity.rating] ?? SEVERITY_STYLES.Informational;
  const confidence = pct(mr.overall_confidence);
  const verdict = lc(mr.verdict);
  const verdictText = VERDICT_TEXT[verdict] || VERDICT_TEXT.unknown;
  const net = countNetworkIOCs(mr);
  const topTTPs: TTPMapping[] = [...mr.ttp_mappings]
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 5);
  const topSigs =
    mr.dynamic?.sandbox_signatures
      ? [...mr.dynamic.sandbox_signatures].sort((a, b) => b.severity - a.severity).slice(0, 5)
      : [];
  const sha256 = mr.identity.hashes.sha256;
  const shortHash = sha256.slice(0, 12);

  // OPS-DEGRADED-VERDICT-01 (audit 2026-05-19): surface the degraded flag
  // from run_summary. Without this banner a 0.6 capped verdict reads the
  // same as a confidently-low real one.
  const runSummary = (report?.run_summary ?? null) as
    | { degraded_mode?: boolean; degradation_reasons?: string[]; failed_analysts?: string[] }
    | null;
  const isDegraded = Boolean(runSummary?.degraded_mode);
  const degradationReasons = runSummary?.degradation_reasons ?? [];
  const failedAnalysts = runSummary?.failed_analysts ?? [];

  return (
    <div className="grid grid-cols-2 gap-4">
      <DownloadBar reportId={reportId} mr={mr} shortHash={shortHash} />

      {isDegraded && (
        <div
          role="alert"
          className="col-span-2 flex items-start gap-3 rounded border border-status-orange/40 bg-status-orange/10 p-3 text-sm"
        >
          <span className="font-semibold text-status-orange shrink-0">
            DEGRADED RUN
          </span>
          <div className="text-text-secondary space-y-1">
            <p>
              Confidence was capped at <span className="font-mono">0.60</span>{" "}
              because the pipeline produced partial signal. Verdict and
              severity should be treated as preliminary.
            </p>
            {degradationReasons.length > 0 && (
              <ul className="list-disc list-inside text-xs">
                {degradationReasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            )}
            {failedAnalysts.length > 0 && (
              <p className="text-xs">
                Failed analysts:{" "}
                <code className="font-mono">{failedAnalysts.join(", ")}</code>
              </p>
            )}
          </div>
        </div>
      )}

      {/* Severity & Verdict card */}
      <div className="bg-bg-surface border border-border rounded col-span-2">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Verdict & Severity
          </h2>
          <code className="text-[10px] font-mono text-text-muted" title={sha256}>
            {sha256.slice(0, 16)}…
          </code>
        </div>
        <div className="p-4 grid grid-cols-4 gap-4">
          <div>
            <div className="text-[10px] text-text-muted uppercase tracking-wider mb-1">
              Verdict
            </div>
            <div className={`text-base font-semibold ${verdictText}`}>{mr.verdict}</div>
          </div>
          <div>
            <div className="text-[10px] text-text-muted uppercase tracking-wider mb-1">
              Confidence
            </div>
            <div className="text-base font-mono">{confidence}/100</div>
          </div>
          <div>
            <div className="text-[10px] text-text-muted uppercase tracking-wider mb-1">
              Severity
            </div>
            <span
              className={`inline-flex items-center gap-2 px-2 py-0.5 rounded text-xs font-medium ${sevStyle.bg} ${sevStyle.border} ${sevStyle.text} border`}
            >
              {mr.severity.rating}
              <span className="font-mono opacity-70">{mr.severity.overall_score.toFixed(1)}/10</span>
            </span>
          </div>
          <div>
            <div className="text-[10px] text-text-muted uppercase tracking-wider mb-1">
              Category
            </div>
            <div className="text-sm text-text-primary">
              {mr.malware_category || mr.attribution.family || "Uncategorized"}
            </div>
          </div>
        </div>
      </div>

      {/* Top TTPs */}
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Top MITRE ATT&amp;CK Techniques
          </h2>
        </div>
        <div className="p-4 space-y-2">
          {topTTPs.length === 0 && (
            <div className="text-xs text-text-muted">No techniques mapped.</div>
          )}
          {topTTPs.map((t) => (
            <div key={t.technique_id} className="flex items-center gap-3">
              <code className="text-[11px] font-mono text-status-blue w-20 shrink-0">
                {t.technique_id}
              </code>
              <span className="text-xs text-text-secondary flex-1 truncate" title={t.technique_name}>
                {t.technique_name}
              </span>
              <span className="text-[10px] font-mono text-text-muted w-12 text-right">
                {Math.round(t.confidence * 100)}%
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Network IOCs summary */}
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Network IOC Snapshot
          </h2>
        </div>
        <div className="p-4 grid grid-cols-4 gap-3 text-center">
          <Stat label="Domains" value={net.domains} />
          <Stat label="IPs" value={net.ips} />
          <Stat label="URLs" value={net.urls} />
          <Stat label="Suspicious" value={net.suspicious} accent="text-status-red" />
        </div>
        {topSigs.length > 0 && (
          <div className="px-4 pb-4">
            <div className="text-[10px] text-text-muted uppercase tracking-wider mb-2">
              Top Sandbox Signatures
            </div>
            <ul className="space-y-1.5">
              {topSigs.map((s) => (
                <li key={s.name} className="flex gap-2 text-xs text-text-secondary">
                  <span className="text-status-orange shrink-0">-</span>
                  <span className="truncate" title={s.description || s.name}>
                    {s.name}
                  </span>
                  <span className="ml-auto text-[10px] font-mono text-text-muted">
                    sev {s.severity}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Executive summary */}
      <div className="col-span-2 bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Executive Summary
          </h2>
        </div>
        <div className="p-4">
          <p className="text-sm text-text-secondary leading-relaxed whitespace-pre-wrap">
            {mr.executive_summary || "Narrative not available for this report."}
          </p>
          {mr.capabilities_narrative.length > 0 && (
            <ul className="mt-3 space-y-2">
              {mr.capabilities_narrative.map((para, i) => (
                <li key={i} className="text-xs text-text-secondary leading-relaxed">
                  <span className="text-text-muted mr-2">{i + 1}.</span>
                  {para}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {/* External References — pulled from MalwareReport.references; the
       * deterministic builder seeds VirusTotal / MalwareBazaar / ATT&CK links
       * for every report so this section is reliably populated. */}
      {mr.references && mr.references.length > 0 && (
        <div className="col-span-2 bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              External References
            </h2>
          </div>
          <ul className="p-4 space-y-1.5">
            {mr.references.map((ref, i) => (
              <li key={`${ref.source}-${i}`} className="flex items-baseline gap-3 text-xs">
                <span className="text-text-muted uppercase tracking-wide w-28 shrink-0">
                  {ref.source}
                </span>
                <a
                  href={ref.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-status-blue hover:underline truncate"
                  title={ref.url}
                >
                  {ref.url}
                </a>
                {ref.note && (
                  <span className="text-text-muted text-[11px] truncate" title={ref.note}>
                    — {ref.note}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent?: string;
}) {
  return (
    <div>
      <div className={`text-2xl font-mono ${accent ?? "text-text-primary"}`}>{value}</div>
      <div className="text-[10px] text-text-muted uppercase tracking-wider">{label}</div>
    </div>
  );
}

function DownloadBar({
  reportId,
  mr,
  shortHash,
}: {
  reportId: string;
  mr: MalwareReport;
  shortHash: string;
}) {
  const [busy, setBusy] = useState<string | null>(null);

  const safeName = `maljan-${shortHash}`;

  const downloadMarkdown = async () => {
    if (!reportId) return;
    setBusy("md");
    try {
      const body = await api.getReportMarkdown(reportId);
      downloadBlob(body, `${safeName}.md`, "text/markdown");
    } catch {
      /* ignore */
    } finally {
      setBusy(null);
    }
  };

  const downloadStix = () => {
    const body = JSON.stringify(mr.stix_bundle_extended, null, 2);
    downloadBlob(body, `${safeName}-stix.json`, "application/json");
  };

  const downloadMisp = () => {
    const body = JSON.stringify(mr.misp_attributes ?? [], null, 2);
    downloadBlob(body, `${safeName}-misp.json`, "application/json");
  };

  const mispDisabled = !mr.misp_attributes || mr.misp_attributes.length === 0;

  return (
    <div className="col-span-2 flex flex-wrap items-center gap-2">
      <span className="text-[10px] text-text-muted uppercase tracking-wider mr-1">
        Export
      </span>
      <button
        onClick={downloadMarkdown}
        disabled={!reportId || busy === "md"}
        className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {busy === "md" ? "fetching..." : "↓ Markdown report"}
      </button>
      <button
        onClick={downloadStix}
        className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors"
      >
        ↓ STIX 2.1 bundle
      </button>
      <button
        onClick={downloadMisp}
        disabled={mispDisabled}
        title={mispDisabled ? "No MISP attributes generated for this report" : undefined}
        className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        ↓ MISP attributes
      </button>
    </div>
  );
}
