"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import type { ProbeResult } from "@/types/settings";
import { isProbeStale } from "../setup/probeStale";

/** Every probe id the catalog can carry has a label here; an id that arrives
 *  without one still gets a usable button ("Test <id>") rather than a blank. */
const PROBE_LABEL: Record<string, string> = {
  llm: "Test connection & fetch models",
  r2: "Test radare2 MCP",
  ghidra: "Test Ghidra MCP",
  capa_yara: "Test capa + YARA rules",
  capa: "Test capa + YARA rules",
  cape2: "Test CAPE connection",
  cape: "Test CAPE connection",
  triage: "Test Triage connection",
  rest: "Test sandbox API",
  mcp: "Test MCP server",
  agent: "Resolve agent",
  qdrant: "Test Qdrant",
  redis: "Test Redis",
  virustotal: "Test VirusTotal",
  abuseipdb: "Test AbuseIPDB",
};

export function probeLabel(id: string): string {
  return PROBE_LABEL[id] ?? `Test ${id}`;
}

export default function GroupHeader({
  title,
  description,
  probes,
  overridden,
  overriddenCount,
  onProbe,
  onResetGroup,
  guideHref,
  probeInputs,
}: {
  title: string;
  description: string;
  probes: string[];
  // "editable" only says a UI-override is *permitted*; it does not mean one
  // exists. Computed by the caller from the group's *full* entry list, not
  // whatever subset the page renders — a currently hidden entry can hold the
  // only override, and removing it must still be offered.
  overridden: boolean;
  overriddenCount: number;
  onProbe: (name: string) => Promise<ProbeResult>;
  onResetGroup: () => Promise<void>;
  guideHref?: string;
  /** A fingerprint of the values the given probe would send right now
   *  (`probeStale.probeFingerprint`). A result taken before one of those
   *  values changed no longer describes what the button would do, so it is
   *  dropped as soon as the fingerprint moves. */
  probeInputs: (probeId: string) => string;
}) {
  /** Each entry remembers the fingerprint of the probe's inputs at the moment
   *  the button was pressed: the result stops being shown as soon as those
   *  values move, because it no longer describes what a press would do. */
  const [results, setResults] = useState<
    Record<string, { result: ProbeResult | "running"; inputsWhenRun: string } | undefined>
  >({});
  const [confirming, setConfirming] = useState(false);

  useEffect(() => {
    if (!confirming) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setConfirming(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [confirming]);

  return (
    <div className="mb-4">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0">
          <h2 className="text-base font-semibold text-text-primary">{title}</h2>
          {description && <p className="text-xs text-text-secondary mt-1">{description}</p>}
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          {guideHref && (
            <Link href={guideHref} className="text-xs text-accent-strong">
              Set up with the guide
            </Link>
          )}
          {overridden && (
            <button
              type="button"
              className="text-[11px] text-text-secondary"
              onClick={() => setConfirming(true)}
            >
              Remove all overrides in this group ({overriddenCount})
            </button>
          )}
        </div>
      </div>

      {probes.length > 0 && (
        <div className="flex items-center gap-4 flex-wrap mt-2">
          {probes.map((name) => {
            const entry = results[name];
            // A running probe stays running-looking no matter what happens to
            // its inputs mid-flight: staleness only describes a *finished*
            // result (does it still reflect what a press would send now), and
            // must never flip a still-running button back to enabled or swap
            // its "testing…" text out from under it.
            const running = entry?.result === "running";
            const stale =
              !running &&
              entry !== undefined &&
              isProbeStale(entry.inputsWhenRun, probeInputs(name));
            const r = entry && !stale ? entry.result : undefined;
            return (
              <span key={name} className="flex items-center gap-2">
                <button
                  type="button"
                  className="text-xs text-accent-strong disabled:opacity-50"
                  disabled={running}
                  onClick={async () => {
                    const inputsWhenRun = probeInputs(name);
                    setResults((s) => ({ ...s, [name]: { result: "running", inputsWhenRun } }));
                    const res = await onProbe(name).catch((e) => ({
                      ok: false,
                      latency_ms: 0,
                      detail: String(e),
                      models: null,
                      tools: null,
                      details: null,
                    }));
                    setResults((s) => ({ ...s, [name]: { result: res, inputsWhenRun } }));
                  }}
                >
                  {probeLabel(name)}
                </button>
                {r && r !== "running" && (
                  <span
                    className={`text-[11px] ${r.ok ? "text-status-green" : "text-status-red"}`}
                    role="status"
                  >
                    {r.ok ? "ok" : "failed"} · {r.latency_ms} ms · {r.detail}
                  </span>
                )}
                {running && <span className="text-[11px] text-text-muted">testing…</span>}
              </span>
            );
          })}
        </div>
      )}

      {confirming && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Remove overrides"
          className="mt-3 border border-border rounded bg-bg-deep px-3 py-2"
        >
          <p className="text-xs text-text-secondary">
            This removes {overriddenCount} stored value(s) from this group now, without Apply.
          </p>
          <div className="flex gap-3 mt-2">
            <button
              type="button"
              className="text-xs text-status-red"
              onClick={async () => {
                setConfirming(false);
                await onResetGroup();
              }}
            >
              Remove {overriddenCount} overrides
            </button>
            <button
              type="button"
              className="text-xs text-text-secondary"
              onClick={() => setConfirming(false)}
            >
              Keep them
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
