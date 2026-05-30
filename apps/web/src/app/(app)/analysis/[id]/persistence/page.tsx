"use client";

import { useReport } from "../layout";
import type { PersistenceKind } from "@/types/malware-report";

const KIND_LABELS: Record<PersistenceKind, string> = {
  // Windows (PE)
  registry_run: "Registry Run Key",
  scheduled_task: "Scheduled Task",
  service: "Windows Service",
  wmi_subscription: "WMI Event Subscription",
  startup_folder: "Startup Folder",
  dll_search_hijacking: "DLL Search Hijacking",
  driver: "Kernel Driver",
  image_hijack: "Image File Execution Options",
  appinit_dll: "AppInit DLL",
  lsa_provider: "LSA Provider",
  winlogon_helper: "Winlogon Helper",
  // Linux (ELF) — Wave 9 (2026-05-29)
  systemd_service: "Systemd Service",
  cron_job: "Cron Job",
  init_d: "init.d Script",
  rc_local: "rc.local Modification",
  ld_preload: "LD_PRELOAD Hijack",
  // Fallback
  other: "Other",
};

const KIND_COLORS: Record<PersistenceKind, string> = {
  registry_run: "text-status-orange bg-status-orange/10",
  scheduled_task: "text-status-blue bg-status-blue/10",
  service: "text-status-red bg-status-red/10",
  wmi_subscription: "text-status-red bg-status-red/10",
  startup_folder: "text-status-orange bg-status-orange/10",
  dll_search_hijacking: "text-status-red bg-status-red/10",
  driver: "text-status-red bg-status-red/10",
  image_hijack: "text-status-red bg-status-red/10",
  appinit_dll: "text-status-red bg-status-red/10",
  lsa_provider: "text-status-red bg-status-red/10",
  winlogon_helper: "text-status-red bg-status-red/10",
  systemd_service: "text-status-red bg-status-red/10",
  cron_job: "text-status-orange bg-status-orange/10",
  init_d: "text-status-red bg-status-red/10",
  rc_local: "text-status-red bg-status-red/10",
  ld_preload: "text-status-red bg-status-red/10",
  other: "text-text-secondary bg-bg-active",
};

export default function PersistenceTab() {
  const { report, loading } = useReport();

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  const items = report?.malware_report?.persistence;
  if (!items || items.length === 0) {
    return (
      <div className="p-8 text-center text-sm text-text-secondary">
        No persistence mechanisms identified for this sample.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {items.map((p, i) => (
        <div
          key={`${p.kind}-${i}`}
          className="bg-bg-surface border border-border rounded p-4"
        >
          <div className="flex items-start gap-3 flex-wrap">
            <span
              className={`text-[11px] uppercase tracking-wider font-medium px-2 py-0.5 rounded shrink-0 ${KIND_COLORS[p.kind]}`}
            >
              {KIND_LABELS[p.kind]}
            </span>
            {p.technique_id && (
              <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-status-blue/10 text-status-blue">
                {p.technique_id}
              </span>
            )}
          </div>
          <div className="mt-2 space-y-2">
            <Row label="Target">
              <code className="text-xs font-mono text-status-blue break-all">{p.target}</code>
            </Row>
            {p.payload && (
              <Row label="Payload">
                <code className="text-xs font-mono text-text-secondary break-all">
                  {p.payload}
                </code>
              </Row>
            )}
            {p.evidence_ref && (
              <Row label="Evidence">
                <span className="text-xs text-text-muted break-all">{p.evidence_ref}</span>
              </Row>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3">
      <span className="text-[11px] uppercase tracking-wider text-text-muted w-16 shrink-0 mt-0.5">
        {label}
      </span>
      <div className="flex-1 min-w-0">{children}</div>
    </div>
  );
}
