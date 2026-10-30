"use client";

import { useMemo, useState } from "react";

import { useReport } from "@/components/analysis/AnalysisContext";
import { downloadBlob } from "@/lib/report-utils";
import CopyButton from "@/components/ui/CopyButton";
import type { DetectionKind, DetectionRule } from "@/types/malware-report";
import { sampleMatchBadge, type SampleMatchTone } from "./sampleMatch";

const KIND_ORDER: DetectionKind[] = ["yara", "sigma", "suricata", "snort"];
const KIND_EXT: Record<DetectionKind, string> = {
  yara: "yar",
  sigma: "yml",
  suricata: "rules",
  snort: "rules",
};
const KIND_MIME: Record<DetectionKind, string> = {
  yara: "text/x-yara",
  sigma: "application/yaml",
  suricata: "text/plain",
  snort: "text/plain",
};
/* Green when the rule's strings match the sample it was drafted from, amber
 * when only a hash clause does, the compile error's red when nothing does,
 * muted when it was not checked. */
const SAMPLE_TONE: Record<SampleMatchTone, string> = {
  strings: "bg-status-green/10 text-status-green",
  hash: "bg-status-orange/10 text-status-orange",
  misses: "bg-status-red/10 text-status-red",
  neutral: "bg-bg-active text-text-muted",
};
const SAMPLE_FOOTER: Record<SampleMatchTone, string> = {
  strings: "text-text-secondary",
  hash: "text-status-orange",
  misses: "text-status-red bg-status-red/5",
  neutral: "text-text-secondary",
};

export default function GeneratedRulesPanel() {
  const { report, loading } = useReport();
  const [activeKind, setActiveKind] = useState<DetectionKind | "all">("all");

  /* The `?? []` is a fresh array on every render, which is a new dependency
   * for both memos below; the report's own list, memoised, is not. */
  const signatures: DetectionRule[] = useMemo(
    () => report?.malware_report?.detection_signatures ?? [],
    [report?.malware_report?.detection_signatures],
  );
  const filtered = useMemo(() => {
    if (activeKind === "all") return signatures;
    return signatures.filter((s) => s.kind === activeKind);
  }, [signatures, activeKind]);

  const presentKinds = useMemo(() => {
    const set = new Set(signatures.map((s) => s.kind));
    return KIND_ORDER.filter((k) => set.has(k));
  }, [signatures]);

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  // The DETECTION tab draws this section only when the run wrote rules, so
  // nothing here has to say that it did not.
  if (signatures.length === 0) return null;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <div className="text-xs text-text-muted">
          {signatures.length} rule{signatures.length !== 1 ? "s" : ""}
        </div>
        <div className="flex gap-1">
          <KindButton
            label={`all (${signatures.length})`}
            active={activeKind === "all"}
            onClick={() => setActiveKind("all")}
          />
          {presentKinds.map((k) => (
            <KindButton
              key={k}
              label={`${k} (${signatures.filter((s) => s.kind === k).length})`}
              active={activeKind === k}
              onClick={() => setActiveKind(k)}
            />
          ))}
        </div>
        {/* One file per kind is in the page's Export menu; each rule below
            keeps its own copy and download. */}
        <span className="ml-auto text-[11px] text-text-muted">
          Every rule of one kind as one file: Export, at the top of the page.
        </span>
      </div>

      <div className="space-y-3">
        {filtered.map((rule, i) => (
          <RuleCard key={`${rule.kind}-${rule.name}-${i}`} rule={rule} />
        ))}
      </div>
    </div>
  );
}

function KindButton({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`text-[11px] uppercase tracking-wider px-2 py-0.5 rounded border ${
        active
          ? "border-accent text-accent"
          : "border-border text-text-secondary hover:text-text-primary"
      }`}
    >
      {label}
    </button>
  );
}

function RuleCard({ rule }: { rule: DetectionRule }) {
  const filename = `${rule.name}.${KIND_EXT[rule.kind]}`;
  const sample = sampleMatchBadge(rule);
  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <span
            className={`text-[11px] uppercase tracking-wider font-medium px-2 py-0.5 rounded shrink-0 ${
              rule.kind === "yara"
                ? "bg-status-purple/10 text-status-purple"
                : rule.kind === "sigma"
                  ? "bg-status-blue/10 text-status-blue"
                  : "bg-status-orange/10 text-status-orange"
            }`}
          >
            {rule.kind}
          </span>
          <code className="text-xs font-mono text-text-primary truncate" title={rule.name}>
            {rule.name}
          </code>
          {rule.auto_generated && (
            <span className="text-[11px] px-1.5 py-0.5 rounded bg-bg-active text-text-muted shrink-0">
              auto-gen
            </span>
          )}
          {rule.compile_error && (
            <span
              className="text-[11px] px-1.5 py-0.5 rounded bg-status-red/10 text-status-red shrink-0"
              title={rule.compile_error}
            >
              compile error
            </span>
          )}
          {sample && (
            <span
              className={`text-[11px] px-1.5 py-0.5 rounded shrink-0 ${SAMPLE_TONE[sample.tone]}`}
              title={sample.detail}
            >
              {sample.label}
            </span>
          )}
        </div>
        <div className="flex gap-2 shrink-0">
          <CopyButton
            value={rule.body}
            what={`${rule.kind} rule ${rule.name}`}
            className="inline-flex min-h-6 items-center px-2 py-1 text-[11px] uppercase tracking-wider text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted"
          />
          <button
            onClick={() => downloadBlob(rule.body, filename, KIND_MIME[rule.kind])}
            className="px-2 py-1 text-[11px] uppercase tracking-wider text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted"
          >
            ↓ {KIND_EXT[rule.kind]}
          </button>
        </div>
      </div>
      <pre className="p-4 text-[11px] font-mono text-text-secondary overflow-x-auto leading-relaxed bg-bg-deep">
        {rule.body}
      </pre>
      {rule.compile_error && (
        <div className="px-4 py-2 border-t border-border text-[11px] text-status-red bg-status-red/5">
          {rule.compile_error}
        </div>
      )}
      {sample && (
        <div className={`px-4 py-2 border-t border-border text-[11px] ${SAMPLE_FOOTER[sample.tone]}`}>
          {sample.detail}
        </div>
      )}
    </div>
  );
}
