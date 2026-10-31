"use client";

import { useMemo, useState } from "react";

import { useReport } from "@/components/analysis/AnalysisContext";
import { downloadBlob } from "@/lib/report-utils";
import CopyButton from "@/components/ui/CopyButton";
import Drawer from "@/components/ui/Drawer";
import ShowMoreRows from "@/components/ui/ShowMoreRows";
import type { DetectionKind, DetectionRule } from "@/types/malware-report";
import { sampleMatchBadge, type SampleMatchTone } from "./sampleMatch";

const KIND_ORDER: DetectionKind[] = ["yara", "sigma", "suricata", "snort"];
const KIND_EXT: Record<DetectionKind, string> = {
  yara: "yar",
  sigma: "yml",
  suricata: "rules",
  snort: "rules",
};
const KIND_LABEL: Record<DetectionKind, string> = {
  yara: "YARA",
  sigma: "Sigma",
  suricata: "Suricata",
  snort: "Snort",
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

/** How many rules the list draws before offering more. */
const RULES_FIRST = 10;

/**
 * Every rule the run wrote, in one list: its kind, its name, whether it
 * compiles and matches the sample it was drafted from, and a copy and a
 * download on each row. A rule's name opens its body in the side panel.
 */
export default function GeneratedRulesPanel() {
  const { report, loading } = useReport();
  const [shown, setShown] = useState(RULES_FIRST);
  const [detail, setDetail] = useState<{ rule: DetectionRule; opener: HTMLElement } | null>(null);

  /* The `?? []` is a fresh array on every render, which is a new dependency
   * for the memo below; the report's own list, memoised, is not. */
  const signatures: DetectionRule[] = useMemo(
    () => report?.malware_report?.detection_signatures ?? [],
    [report?.malware_report?.detection_signatures],
  );
  // Grouped by kind, in the order an analyst deploys them; each kind keeps
  // the order the run wrote it in.
  const ordered = useMemo(
    () => KIND_ORDER.flatMap((k) => signatures.filter((s) => s.kind === k)).concat(
      signatures.filter((s) => !KIND_ORDER.includes(s.kind)),
    ),
    [signatures],
  );

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }
  if (signatures.length === 0) return null;

  return (
    <div className="space-y-3">
      {/* One file per kind is in the page's Export menu; each rule below
          keeps its own copy and download. */}
      <p className="text-[11px] text-text-muted">Every rule of one kind as one file: Export, at the top of the page.</p>
      <ul className="divide-y divide-border-light rounded border border-border-light">
        {ordered.slice(0, shown).map((rule, i) => (
          <RuleRow
            key={`${rule.kind}-${rule.name}-${i}`}
            rule={rule}
            onOpen={(opener) => setDetail({ rule, opener })}
          />
        ))}
      </ul>
      <ShowMoreRows shown={Math.min(shown, ordered.length)} total={ordered.length} onShow={setShown} step={RULES_FIRST} />
      <Drawer
        open={detail !== null}
        title={detail ? detail.rule.name : ""}
        onClose={() => setDetail(null)}
        returnFocusTo={detail?.opener ?? null}
      >
        {detail && <RuleBody rule={detail.rule} />}
      </Drawer>
    </div>
  );
}

function KindTag({ kind }: { kind: DetectionKind }) {
  return (
    <span
      className={`shrink-0 rounded px-2 py-0.5 text-[11px] font-medium ${
        kind === "yara"
          ? "bg-status-purple/10 text-status-purple"
          : kind === "sigma"
            ? "bg-status-blue/10 text-status-blue"
            : "bg-status-orange/10 text-status-orange"
      }`}
    >
      {KIND_LABEL[kind] ?? kind}
    </span>
  );
}

function RuleRow({ rule, onOpen }: { rule: DetectionRule; onOpen: (opener: HTMLElement) => void }) {
  const filename = `${rule.name}.${KIND_EXT[rule.kind]}`;
  const sample = sampleMatchBadge(rule);
  return (
    <li className="flex flex-wrap items-center gap-2 px-3 py-2">
      <KindTag kind={rule.kind} />
      <button
        type="button"
        onClick={(e) => onOpen(e.currentTarget)}
        title={rule.name}
        className="min-w-0 max-w-full truncate text-left font-mono text-xs text-text-primary hover:underline"
      >
        {rule.name}
      </button>
      {rule.auto_generated && (
        <span className="shrink-0 rounded bg-bg-active px-1.5 py-0.5 text-[11px] text-text-muted">auto-generated</span>
      )}
      {rule.compile_error && (
        <span className="shrink-0 rounded bg-status-red/10 px-1.5 py-0.5 text-[11px] text-status-red" title={rule.compile_error}>
          compile error
        </span>
      )}
      {sample && (
        <span className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] ${SAMPLE_TONE[sample.tone]}`} title={sample.detail}>
          {sample.label}
        </span>
      )}
      <span className="ml-auto flex shrink-0 gap-2">
        <CopyButton value={rule.body} what={`${rule.kind} rule ${rule.name}`} />
        <button
          type="button"
          onClick={() => downloadBlob(rule.body, filename, KIND_MIME[rule.kind])}
          aria-label={`Download ${rule.kind} rule ${rule.name}`}
          className="inline-flex min-h-6 items-center rounded border border-border px-2 py-0.5 text-[11px] text-text-secondary hover:border-text-muted hover:text-text-primary"
        >
          .{KIND_EXT[rule.kind]}
        </button>
      </span>
    </li>
  );
}

function RuleBody({ rule }: { rule: DetectionRule }) {
  const sample = sampleMatchBadge(rule);
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <KindTag kind={rule.kind} />
        <CopyButton value={rule.body} what={`${rule.kind} rule ${rule.name}`} />
      </div>
      <pre className="overflow-x-auto rounded border border-border-light bg-bg-deep p-3 font-mono text-[11px] leading-relaxed text-text-secondary">
        {rule.body}
      </pre>
      {rule.compile_error && (
        <p className="rounded bg-status-red/5 px-2 py-1.5 text-[11px] text-status-red">{rule.compile_error}</p>
      )}
      {sample && <p className={`rounded px-2 py-1.5 text-[11px] ${SAMPLE_FOOTER[sample.tone]}`}>{sample.detail}</p>}
    </div>
  );
}
