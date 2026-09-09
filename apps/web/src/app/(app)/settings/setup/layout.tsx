"use client";

import type { ReactNode } from "react";

/** The guides share `settings/layout.tsx`'s `SettingsProvider`; this layout
 *  exists so the route segment has one of its own to grow into. */
export default function SetupLayout({ children }: { children: ReactNode }) {
  return <div>{children}</div>;
}
