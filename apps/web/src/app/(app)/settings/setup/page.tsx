"use client";

import Link from "next/link";
import { Bot, Brain, Database, FlaskConical, Radar, Server, Wrench } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { useSettingsContext } from "../configuration/SettingsContext";
import { guidesFor, type GuideId } from "./guides";
import { guideStatus, llmLooksConfigured } from "./status";

/** One icon per guide, so the hub is scannable before it is read. */
const GUIDE_ICON: Record<GuideId, LucideIcon> = {
  llm: Brain,
  static: Wrench,
  sandbox: FlaskConical,
  "tool-server": Server,
  agent: Bot,
  memory: Database,
  enrichment: Radar,
};

/**
 * The guide hub: one card per guide, with the status line the current values
 * produce. A guide that has no definition yet is simply not listed — the hub
 * never links at a route that would 404.
 *
 * Before a language model is connected it lists the four a first run needs and
 * nothing else. A tool server, a memory backend and threat-intel enrichment
 * all improve a pipeline that already runs; offered to somebody whose analysts
 * cannot talk to a model yet, they are four more decisions between them and
 * the one that matters.
 */
export default function SetupHubPage() {
  const ctx = useSettingsContext();
  const isSet = (key: string) => ctx.values[key]?.is_set === true;
  const configured = llmLooksConfigured(ctx.effectiveValue, isSet);
  const guides = guidesFor(configured);

  return (
    <section>
      <h2 className="text-base font-semibold text-text-primary">Setup guides</h2>
      <p className="text-xs text-text-secondary mt-1 mb-4">
        {configured
          ? "Step-by-step setup for the same settings the console holds. Values you enter here are staged the same way and applied in one save."
          : "Four steps to a first analysis. Connect a model first — the rest are tested against it. More guides appear once it is connected."}
      </p>

      <ul className="grid gap-3 sm:grid-cols-2">
        {guides.map((guide) => {
          const Icon = GUIDE_ICON[guide.id];
          return (
            <li key={guide.id} className="border border-border rounded bg-bg-surface px-4 py-3">
              <h3 className="flex items-center gap-2 text-sm font-medium text-text-primary">
                <Icon size={18} aria-hidden="true" className="text-text-muted" />
                {guide.title}
              </h3>
              <p className="text-xs text-text-secondary mt-1">{guide.blurb}</p>
              <p className="text-xs text-text-muted mt-2">
                <span className="uppercase tracking-wider text-[11px]">Now:</span>{" "}
                <span data-testid={`guide-status-${guide.id}`}>
                  {guideStatus(guide.id, ctx.effectiveValue, isSet)}
                </span>
              </p>
              <Link
                href={`/settings/setup/${guide.id}`}
                className="inline-block mt-3 px-3 py-1.5 text-xs font-medium uppercase tracking-wider bg-accent text-white rounded hover:bg-accent-hover"
              >
                Start
              </Link>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
