"use client";

import { useReport } from "../layout";
import { PRIORITY_STYLES } from "@/types/malware-report";
import type { DefensiveCategory, Priority } from "@/types/malware-report";

const CATEGORY_LABELS: Record<DefensiveCategory, string> = {
  firewall: "Firewall / Network",
  edr_hunting: "EDR Hunting",
  registry_hardening: "Registry Hardening",
  gpo: "Group Policy",
  patching: "Patching",
  user_awareness: "User Awareness",
  other: "Other",
};

const PRIORITY_ORDER: Priority[] = ["P0", "P1", "P2"];

export default function DefenseTab() {
  const { report, loading } = useReport();

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  const recommendations = report?.malware_report?.defensive_recommendations ?? [];
  if (recommendations.length === 0) {
    return (
      <div className="p-8 text-center text-sm text-text-secondary">
        No defensive recommendations available for this report.
      </div>
    );
  }

  const groups = PRIORITY_ORDER.map((p) => ({
    priority: p,
    items: recommendations.filter((r) => r.priority === p),
  })).filter((g) => g.items.length > 0);

  return (
    <div className="space-y-6">
      {groups.map(({ priority, items }) => {
        const style = PRIORITY_STYLES[priority];
        return (
          <div key={priority}>
            <div className="flex items-center gap-2 mb-3">
              <span
                className={`text-[11px] uppercase tracking-wider font-medium px-2 py-0.5 rounded ${style.text} ${style.bg}`}
              >
                {style.label}
              </span>
              <span className="text-xs text-text-muted">
                {items.length} action{items.length !== 1 ? "s" : ""}
              </span>
            </div>
            <div className="space-y-3">
              {items.map((rec, i) => (
                <div
                  key={`${priority}-${i}`}
                  className="bg-bg-surface border border-border rounded p-4"
                >
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-[11px] uppercase tracking-wider text-text-muted">
                      {CATEGORY_LABELS[rec.category]}
                    </span>
                  </div>
                  <div className="text-sm text-text-primary leading-relaxed">{rec.action}</div>
                  <div className="text-sm text-text-secondary leading-relaxed mt-2 border-l-2 border-border-light pl-3">
                    <span className="text-text-muted">Why: </span>
                    {rec.rationale}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
