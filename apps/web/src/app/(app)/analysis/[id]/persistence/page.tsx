"use client";

import { useReport } from "../layout";
import type { PersistenceKind } from "@/types/malware-report";
import { ArtifactSections } from "@/components/analysis/ArtifactTable";
import { sectionsForTab } from "@/components/analysis/reportSections";

const KIND_LABELS: Record<PersistenceKind, string> = {
  // Windows (PE)
  registry_run: "Registry Run Key",
  scheduled_task: "Scheduled Task",
  service: "Windows Service",
  wmi_subscription: "WMI Event Subscription",
  com_hijacking: "COM Hijacking",
  startup_folder: "Startup Folder",
  dll_search_hijacking: "DLL Search Hijacking",
  driver: "Kernel Driver",
  image_hijack: "Image File Execution Options",
  appinit_dll: "AppInit DLL",
  lsa_provider: "LSA Provider",
  winlogon_helper: "Winlogon Helper",
  // Linux (ELF)
  systemd_service: "Systemd Service",
  systemd_timer: "Systemd Timer",
  cron_job: "Cron Job",
  init_d: "init.d Script",
  rc_local: "rc.local Modification",
  ld_preload: "LD_PRELOAD Hijack",
  xdg_autostart: "XDG Autostart",
  shell_profile: "Shell Profile",
  udev_rule: "udev Rule",
  kernel_module: "Kernel Module",
  // macOS (Mach-O)
  launch_agent: "Launch Agent",
  launch_daemon: "Launch Daemon",
  login_item: "Login Item",
  kernel_extension: "Kernel Extension",
  configuration_profile: "Configuration Profile",
  // Android (APK/DEX)
  boot_receiver: "Boot Receiver",
  device_admin: "Device Admin",
  accessibility_service: "Accessibility Service",
  foreground_service: "Foreground Service",
  work_scheduler: "Scheduled Work",
  // Fallback
  other: "Other",
};

const KIND_COLORS: Record<PersistenceKind, string> = {
  registry_run: "text-status-orange bg-status-orange/10",
  scheduled_task: "text-status-blue bg-status-blue/10",
  service: "text-status-red bg-status-red/10",
  wmi_subscription: "text-status-red bg-status-red/10",
  com_hijacking: "text-status-red bg-status-red/10",
  startup_folder: "text-status-orange bg-status-orange/10",
  dll_search_hijacking: "text-status-red bg-status-red/10",
  driver: "text-status-red bg-status-red/10",
  image_hijack: "text-status-red bg-status-red/10",
  appinit_dll: "text-status-red bg-status-red/10",
  lsa_provider: "text-status-red bg-status-red/10",
  winlogon_helper: "text-status-red bg-status-red/10",
  systemd_service: "text-status-red bg-status-red/10",
  systemd_timer: "text-status-red bg-status-red/10",
  cron_job: "text-status-orange bg-status-orange/10",
  init_d: "text-status-red bg-status-red/10",
  rc_local: "text-status-red bg-status-red/10",
  ld_preload: "text-status-red bg-status-red/10",
  xdg_autostart: "text-status-orange bg-status-orange/10",
  shell_profile: "text-status-orange bg-status-orange/10",
  udev_rule: "text-status-red bg-status-red/10",
  kernel_module: "text-status-red bg-status-red/10",
  launch_agent: "text-status-orange bg-status-orange/10",
  launch_daemon: "text-status-red bg-status-red/10",
  login_item: "text-status-orange bg-status-orange/10",
  kernel_extension: "text-status-red bg-status-red/10",
  configuration_profile: "text-status-red bg-status-red/10",
  boot_receiver: "text-status-orange bg-status-orange/10",
  device_admin: "text-status-red bg-status-red/10",
  accessibility_service: "text-status-red bg-status-red/10",
  foreground_service: "text-status-orange bg-status-orange/10",
  work_scheduler: "text-status-orange bg-status-orange/10",
  other: "text-text-secondary bg-bg-active",
};

export default function PersistenceTab() {
  const { report, loading } = useReport();

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  const items = report?.malware_report?.persistence;
  const evidenceSections = sectionsForTab(report?.malware_report?.sections, "persistence");
  if ((!items || items.length === 0) && evidenceSections.length === 0) {
    return (
      <div className="p-8 text-center text-sm text-text-secondary">
        No persistence mechanisms identified for this sample.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <ArtifactSections sections={evidenceSections} />
      {(items ?? []).map((p, i) => (
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
