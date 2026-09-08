"use client";

import { Suspense, useState } from "react";
import type { ReactNode } from "react";
import ApplyBar from "./ApplyBar";
import SectionRail from "./SectionRail";
import { SettingsProvider, useSettingsContext } from "./SettingsContext";
import Toolbar from "./Toolbar";
import { appliesSummary } from "./vocabulary";

function ConfigurationLayoutBody({ children }: { children: ReactNode }) {
  const s = useSettingsContext();
  const [confirming, setConfirming] = useState(false);

  return (
    <div>
      <Suspense fallback={null}>
        <Toolbar />
      </Suspense>
      {s.lastResult && (
        <div className="text-xs text-status-green mb-3" role="status">
          {appliesSummary(s.lastResult.applies, s.lastResult.applied.length)}
        </div>
      )}
      <div className="lg:grid lg:grid-cols-[240px_minmax(0,1fr)] gap-6">
        <SectionRail />
        <div className="min-w-0">{children}</div>
      </div>
      <ApplyBar
        pending={s.pending}
        entries={s.entries}
        hiddenKeys={s.hiddenKeys}
        saving={s.saving}
        confirming={confirming}
        setConfirming={setConfirming}
        onApply={async () => {
          const r = await s.apply();
          if (r) setConfirming(false);
        }}
        onDiscard={() => Object.keys(s.pending).forEach((k) => s.unstage(k))}
      />
    </div>
  );
}

export default function ConfigurationLayout({ children }: { children: ReactNode }) {
  return (
    <SettingsProvider>
      <ConfigurationLayoutBody>{children}</ConfigurationLayoutBody>
    </SettingsProvider>
  );
}
