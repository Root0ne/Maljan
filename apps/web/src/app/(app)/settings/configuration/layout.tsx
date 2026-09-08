"use client";

import { useState } from "react";
import type { ReactNode } from "react";
import ApplyBar from "./ApplyBar";
import SectionRail from "./SectionRail";
import { SettingsProvider, useSettingsContext } from "./SettingsContext";

function ConfigurationLayoutBody({ children }: { children: ReactNode }) {
  const s = useSettingsContext();
  const [confirming, setConfirming] = useState(false);

  return (
    <div>
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
