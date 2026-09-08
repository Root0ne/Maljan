"use client";

import { Suspense } from "react";
import type { ReactNode } from "react";
import ChangesBar from "./ChangesBar";
import SectionRail from "./SectionRail";
import Toolbar from "./Toolbar";

/** `SettingsProvider` lives in `settings/layout.tsx` (one provider for the
 *  console and the guides alike), so this layout only lays the console out. */
export default function ConfigurationLayout({ children }: { children: ReactNode }) {
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
