"use client";

import Link from "next/link";
import { useState } from "react";

interface ReportRow {
  id: string;
  job_id: string;
  sample_filename: string;
  final_verdict: string;
  confidence_score: number;
  created_at: string;
  techniques_count: number;
  yara_count: number;
  sigma_count: number;
}

const VERDICT_STYLES: Record<string, { dot: string; text: string }> = {
  malicious: { dot: "bg-status-red", text: "text-status-red" },
  suspicious: { dot: "bg-status-orange", text: "text-status-orange" },
  benign: { dot: "bg-status-green", text: "text-status-green" },
  unknown: { dot: "bg-text-muted", text: "text-text-muted" },
};

const MOCK_REPORTS: ReportRow[] = [
  { id: "11111111-1111-1111-1111-111111111111", job_id: "11111111-1111-1111-1111-111111111111", sample_filename: "emotet_dropper.exe", final_verdict: "malicious", confidence_score: 87, created_at: "2026-05-02T14:30:00Z", techniques_count: 18, yara_count: 5, sigma_count: 5 },
  { id: "22222222-2222-2222-2222-222222222222", job_id: "22222222-2222-2222-2222-222222222222", sample_filename: "invoice_macro.docm", final_verdict: "malicious", confidence_score: 92, created_at: "2026-05-02T12:15:00Z", techniques_count: 12, yara_count: 3, sigma_count: 4 },
  { id: "33333333-3333-3333-3333-333333333333", job_id: "33333333-3333-3333-3333-333333333333", sample_filename: "setup_tool.msi", final_verdict: "suspicious", confidence_score: 58, created_at: "2026-05-01T09:45:00Z", techniques_count: 6, yara_count: 1, sigma_count: 2 },
  { id: "44444444-4444-4444-4444-444444444444", job_id: "44444444-4444-4444-4444-444444444444", sample_filename: "readme.pdf", final_verdict: "benign", confidence_score: 12, created_at: "2026-04-30T16:20:00Z", techniques_count: 0, yara_count: 0, sigma_count: 0 },
  { id: "55555555-5555-5555-5555-555555555555", job_id: "55555555-5555-5555-5555-555555555555", sample_filename: "lockbit3_payload.dll", final_verdict: "malicious", confidence_score: 96, created_at: "2026-04-30T11:00:00Z", techniques_count: 24, yara_count: 8, sigma_count: 7 },
  { id: "66666666-6666-6666-6666-666666666666", job_id: "66666666-6666-6666-6666-666666666666", sample_filename: "chrome_update.exe", final_verdict: "malicious", confidence_score: 81, created_at: "2026-04-29T08:30:00Z", techniques_count: 14, yara_count: 4, sigma_count: 3 },
];

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function ReportsPage() {
  const [filter, setFilter] = useState<string>("all");

  const filtered =
    filter === "all"
      ? MOCK_REPORTS
      : MOCK_REPORTS.filter((r) => r.final_verdict === filter);

  return (
    <div>
      {/* Page Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-lg font-semibold text-text-primary">Reports</h1>
          <p className="text-xs text-text-secondary mt-0.5">
            {MOCK_REPORTS.length} analysis reports generated
          </p>
        </div>
        <div className="flex gap-2">
          <button className="h-8 px-3 text-xs bg-bg-surface border border-border rounded text-text-secondary hover:text-text-primary hover:border-text-muted transition-colors">
            Export All (JSON)
          </button>
          <button className="h-8 px-3 text-xs bg-bg-surface border border-border rounded text-text-secondary hover:text-text-primary hover:border-text-muted transition-colors">
            Export All (CSV)
          </button>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex gap-1 mb-4 border-b border-border">
        {[
          { key: "all", label: "All" },
          { key: "malicious", label: "Malicious" },
          { key: "suspicious", label: "Suspicious" },
          { key: "benign", label: "Benign" },
        ].map((f) => (
          <button
            key={f.key}
            onClick={() => setFilter(f.key)}
            className={`px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
              filter === f.key
                ? "border-accent text-accent"
                : "border-transparent text-text-secondary hover:text-text-primary"
            }`}
          >
            {f.label}
            <span className="ml-1.5 text-text-muted">
              ({f.key === "all" ? MOCK_REPORTS.length : MOCK_REPORTS.filter((r) => r.final_verdict === f.key).length})
            </span>
          </button>
        ))}
      </div>

      {/* Reports Table */}
      <div className="bg-bg-surface border border-border rounded">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2.5 uppercase tracking-wider">Sample</th>
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2.5 uppercase tracking-wider w-28">Verdict</th>
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2.5 uppercase tracking-wider w-24">Score</th>
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2.5 uppercase tracking-wider w-20">TTPs</th>
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2.5 uppercase tracking-wider w-20">YARA</th>
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2.5 uppercase tracking-wider w-20">Sigma</th>
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2.5 uppercase tracking-wider w-36">Date</th>
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2.5 uppercase tracking-wider w-32">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-light">
            {filtered.map((report) => {
              const v = VERDICT_STYLES[report.final_verdict] || VERDICT_STYLES.unknown;
              return (
                <tr key={report.id} className="hover:bg-bg-hover transition-colors">
                  <td className="px-4 py-3">
                    <Link
                      href={`/analysis/${report.job_id}`}
                      className="text-sm text-accent hover:underline"
                    >
                      {report.sample_filename}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <div className={`flex items-center gap-1.5 ${v.text}`}>
                      <span className={`w-2 h-2 rounded-full ${v.dot}`} />
                      <span className="text-xs capitalize">{report.final_verdict}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-10 h-1.5 bg-bg-deep rounded-sm overflow-hidden">
                        <div
                          className="h-full rounded-sm"
                          style={{
                            width: `${report.confidence_score}%`,
                            backgroundColor: report.confidence_score >= 70 ? "var(--status-red)" : report.confidence_score >= 40 ? "var(--status-orange)" : "var(--status-green)",
                            opacity: 0.7,
                          }}
                        />
                      </div>
                      <span className="text-xs text-text-secondary font-mono">{report.confidence_score}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-text-secondary">{report.techniques_count}</td>
                  <td className="px-4 py-3 text-xs text-text-secondary">{report.yara_count}</td>
                  <td className="px-4 py-3 text-xs text-text-secondary">{report.sigma_count}</td>
                  <td className="px-4 py-3 text-xs text-text-muted">{formatDate(report.created_at)}</td>
                  <td className="px-4 py-3">
                    <div className="flex gap-1.5">
                      <button
                        className="px-2 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors"
                        title="Download PDF"
                      >
                        PDF
                      </button>
                      <button
                        className="px-2 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors"
                        title="Download JSON"
                      >
                        JSON
                      </button>
                      <button
                        className="px-2 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors"
                        title="Download STIX"
                      >
                        STIX
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>

        {filtered.length === 0 && (
          <div className="px-4 py-8 text-center text-xs text-text-muted">
            No reports match the selected filter.
          </div>
        )}
      </div>
    </div>
  );
}
