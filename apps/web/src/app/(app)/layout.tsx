"use client";

import { AuthProvider } from "@/lib/auth";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider>
      <div className="flex h-screen overflow-hidden">
        <Sidebar />
        {/* `min-w-0` on both flex children, and it is not cosmetic. A flex item
            defaults to `min-width: auto`, so it grows to its content's
            min-content width instead of constraining it: one wide `<pre>` on
            the Detection tab took `main` to 2542 px inside a 1440 px window and
            the shell's `overflow:hidden` cut the rest off with no scrollbar
            anywhere to reach it. With the minimum at zero the column stays the
            width of the viewport and the scrollers inside it — every
            `overflow-x-auto` table and code block — engage as they were meant
            to. */}
        <div
          className="flex flex-col flex-1 min-w-0"
          style={{ marginLeft: "var(--sidebar-width)" }}
        >
          <Header />
          <main className="flex-1 min-w-0 overflow-y-auto p-6">
            {children}
          </main>
        </div>
      </div>
    </AuthProvider>
  );
}
