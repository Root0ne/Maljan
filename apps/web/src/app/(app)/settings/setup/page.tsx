"use client";

import Link from "next/link";
import { useSettingsContext } from "../configuration/SettingsContext";
import { GUIDES } from "./guides";
import { guideStatus } from "./status";

/**
 * The guide hub: one card per guide in `GUIDES`, with the status line the
 * current values produce. A guide that has no definition yet is simply not
 * listed — the hub never links at a route that would 404.
 */
export default function SetupHubPage() {
  const ctx = useSettingsContext();
  const isSet = (key: string) => ctx.values[key]?.is_set === true;

  return (
    <section>
      <h2 className="text-base font-semibold text-text-primary">Setup guides</h2>
      <p className="text-xs text-text-secondary mt-1 mb-4">
        Step-by-step setup for the same settings the console holds. Values you enter here are
        staged the same way and applied in one save.
      </p>

      <ul className="grid gap-3 sm:grid-cols-2">
        {GUIDES.map((guide) => (
          <li key={guide.id} className="border border-border rounded bg-bg-surface px-4 py-3">
            <h3 className="text-sm font-medium text-text-primary">{guide.title}</h3>
            <p className="text-xs text-text-secondary mt-1">{guide.blurb}</p>
            <p className="text-xs text-text-muted mt-2">
              <span className="uppercase tracking-wider text-[11px]">Now:</span>{" "}
              <span data-testid={`guide-status-${guide.id}`}>
                {guideStatus(guide.id, ctx.effectiveValue, isSet)}
              </span>
            </p>
            <Link
              href={`/settings/setup/${guide.id}`}
              className="inline-block mt-3 px-3 py-1.5 text-xs font-medium uppercase tracking-wider bg-accent text-white rounded hover:bg-accent-hover transition-colors"
            >
              Start
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
