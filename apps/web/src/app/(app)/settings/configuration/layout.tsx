"use client";

import { Suspense } from "react";
import type { ReactNode } from "react";
import ChangesBar from "./ChangesBar";
import SectionRail from "./SectionRail";
import { SettingsProvider } from "./SettingsContext";
import Toolbar from "./Toolbar";

function ConfigurationLayoutBody({ children }: { children: ReactNode }) {
  return (
    <div>
      <Suspense fallback={null}>
        <Toolbar />
      </Suspense>
      <div className="lg:grid lg:grid-cols-[240px_minmax(0,1fr)] gap-6">
        <SectionRail />
        <div className="min-w-0">{children}</div>
      </div>
      <ChangesBar />
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
