import Link from "next/link";
import Section from "@/components/ui/Section";
import { usePreview } from "./PreviewFrame";
import type { PreviewTab } from "./overview";

/** Where today's console shows what a placeholder tab will hold. */
const TODAY: Record<string, { label: string; path: string }[]> = {
  behaviour: [
    { label: "Dynamic", path: "/dynamic" },
    { label: "ATT&CK", path: "/capabilities" },
    { label: "Persistence", path: "/persistence" },
  ],
  network: [{ label: "Network", path: "/network" }],
  static: [
    { label: "Identity", path: "/identity" },
    { label: "Static", path: "/static" },
  ],
  indicators: [{ label: "Detection", path: "/detection" }],
  evidence: [
    { label: "Evidence", path: "/evidence" },
    { label: "Conversation", path: "/conversation" },
  ],
};

/**
 * A tab of the preview that is not built yet: what it will hold, and where
 * today's console already shows that content.
 */
export default function PlaceholderTab({ tab }: { tab: PreviewTab }) {
  const { jobId } = usePreview();
  const links = TODAY[tab.key] ?? [];
  return (
    <Section title={`${tab.label}: coming next`}>
      <div className="max-w-[72ch] space-y-3 text-sm">
        <p className="text-text-secondary">This tab is not built yet in the preview. It will hold:</p>
        <ul className="list-disc space-y-1 pl-5 text-text-primary">
          {tab.planned.map((p) => (
            <li key={p}>{p}</li>
          ))}
        </ul>
        {links.length > 0 && (
          <p className="text-text-secondary">
            Today this content is on{" "}
            {links.map((l, i) => (
              <span key={l.path}>
                {i > 0 && (i === links.length - 1 ? " and " : ", ")}
                <Link
                  href={`/analysis/${encodeURIComponent(jobId)}${l.path}`}
                  className="text-accent-strong hover:underline"
                >
                  {l.label}
                </Link>
              </span>
            ))}
            .
          </p>
        )}
      </div>
    </Section>
  );
}
