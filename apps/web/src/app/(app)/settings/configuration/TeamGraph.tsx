"use client";

import { useState } from "react";
import type { TeamFinding, TeamGraph as TeamGraphData } from "@/types/settings";
import {
  NODE_HEIGHT,
  NODE_WIDTH,
  clip,
  nodeSummary,
  placeGraph,
  teamFindings,
  worstOf,
  type Severity,
} from "./teamGraph";

/** One flat colour per stage kind, from the theme's tokens, on the box's edge. */
const KIND_FILL: Record<string, string> = {
  triage: "fill-status-green",
  analysis: "fill-status-blue",
  debate: "fill-status-purple",
  verdict: "fill-accent-strong",
  report: "fill-text-muted",
};

const FRAME: Record<Severity | "clean", string> = {
  error: "stroke-status-red",
  warning: "stroke-status-orange",
  clean: "stroke-border",
};

const LABEL: Record<Severity, string> = { error: "Error", warning: "Warning" };

/**
 * The team as the graph it runs as, beside the stage cards, and its findings.
 *
 * Stages are boxes placed by the shared team layout, `depends_on` the arrows
 * between them; a dashed box runs only when its condition holds, a dashed
 * arrow is the triage pack starting a stage that names no dependency, and a
 * red arrow bending up the right is a dependency on a stage written further
 * down — which apply refuses. A stage with a finding has a red or orange
 * frame and says how many.
 *
 * Every stage is a button: Enter or Space moves focus to its card. The list
 * under the picture says everything the picture does, in words, so nothing
 * here is available only as a shape or a colour.
 */
export default function TeamGraph({
  team,
  graph,
  findings,
  checking,
  onSelectStage,
}: {
  team: string;
  graph: TeamGraphData | undefined;
  findings: TeamFinding[];
  /** A check of the current edit is in flight; the picture is the last one. */
  checking: boolean;
  onSelectStage: (stage: string) => void;
}) {
  const [focused, setFocused] = useState<string | null>(null);
  const { byStage, team: whole } = teamFindings(findings, team);
  const listed = [...whole, ...[...byStage.values()].flat()].sort(
    (a, b) => Number(a.severity === "warning") - Number(b.severity === "warning")
  );
  const errors = listed.filter((f) => f.severity === "error").length;
  const warnings = listed.length - errors;

  if (!graph) {
    return (
      <p className="text-[11px] text-text-muted" role="status">
        {checking ? "Checking the team…" : "No preview yet."}
      </p>
    );
  }

  const placed = placeGraph(graph, findings, team);
  const summary =
    errors + warnings === 0
      ? "No problems found. Apply will accept this team."
      : [
          errors ? `${errors} ${errors === 1 ? "error" : "errors"} apply will refuse` : "",
          warnings ? `${warnings} ${warnings === 1 ? "warning" : "warnings"}` : "",
        ]
          .filter(Boolean)
          .join(", ") + ".";

  return (
    <section aria-label={`${team} team preview`} className="space-y-2" data-team-graph={team}>
      <div className="flex items-center justify-between gap-2">
        <h4 className="text-[11px] uppercase tracking-wider text-text-muted">Stage graph</h4>
        <span className="text-[10px] text-text-muted" role="status" aria-live="polite">
          {checking ? "Checking…" : ""}
        </span>
      </div>
      <div className="overflow-x-auto rounded border border-border bg-bg-deep">
        <svg
          width={placed.width}
          height={placed.height}
          viewBox={`0 0 ${placed.width} ${placed.height}`}
          role="group"
          aria-label={`Stages of the ${team} team and what each depends on`}
          className={checking ? "opacity-70" : undefined}
        >
          <defs>
            <marker
              id={`team-arrow-${team}`}
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" className="fill-text-muted" />
            </marker>
          </defs>
          {placed.edges.map((edge) => (
            <path
              key={`${edge.source}->${edge.target}:${edge.legal}`}
              d={edge.d}
              fill="none"
              strokeWidth={edge.legal ? 1.5 : 2}
              strokeDasharray={edge.implicit ? "4 3" : edge.legal ? undefined : "6 3"}
              className={edge.legal ? "stroke-text-muted" : "stroke-status-red"}
              markerEnd={`url(#team-arrow-${team})`}
            />
          ))}
          {placed.nodes.map((node) => {
            const tone = FRAME[node.worst ?? "clean"];
            const count = node.findings.length;
            return (
              <g
                key={node.key}
                role="button"
                tabIndex={0}
                aria-label={nodeSummary(node)}
                className="cursor-pointer outline-none"
                onClick={() => onSelectStage(node.key)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    onSelectStage(node.key);
                  }
                }}
                onFocus={() => setFocused(node.key)}
                onBlur={() => setFocused((current) => (current === node.key ? null : current))}
                data-stage-node={node.key}
              >
                {focused === node.key && (
                  <rect
                    x={node.x - 3}
                    y={node.y - 3}
                    width={NODE_WIDTH + 6}
                    height={NODE_HEIGHT + 6}
                    rx={7}
                    fill="none"
                    strokeWidth={2}
                    className="stroke-accent-strong"
                  />
                )}
                <rect
                  x={node.x}
                  y={node.y}
                  width={NODE_WIDTH}
                  height={NODE_HEIGHT}
                  rx={5}
                  strokeWidth={node.worst ? 2 : 1}
                  strokeDasharray={node.when ? "4 3" : undefined}
                  className={`fill-bg-elevated ${tone}`}
                />
                <rect
                  x={node.x}
                  y={node.y}
                  width={4}
                  height={NODE_HEIGHT}
                  rx={2}
                  className={KIND_FILL[node.kind] ?? "fill-text-disabled"}
                />
                <text x={node.x + 12} y={node.y + 18} className="fill-text-primary font-mono" fontSize={12}>
                  {clip(node.key, 16)}
                  <tspan className="fill-text-muted" fontSize={10}>
                    {"  "}
                    {node.kind}
                  </tspan>
                </text>
                <text x={node.x + 12} y={node.y + 33} className="fill-text-secondary" fontSize={10}>
                  {clip(node.agents.join(", ") || "no agent", 28)}
                </text>
                <text x={node.x + 12} y={node.y + 47} className="fill-accent-strong font-mono" fontSize={10}>
                  {node.when ? clip(`when ${node.when}`, 28) : ""}
                </text>
                {count > 0 && (
                  <text
                    x={node.x + NODE_WIDTH - 8}
                    y={node.y + 18}
                    textAnchor="end"
                    fontSize={10}
                    className={node.worst === "error" ? "fill-status-red" : "fill-status-orange"}
                  >
                    {`${count} ${node.worst === "error" ? "err" : "warn"}`}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>

      <p className={`text-[11px] ${errors ? "text-status-red" : warnings ? "text-status-orange" : "text-status-green"}`}>
        {summary}
      </p>
      {listed.length > 0 && (
        <ul className="space-y-1" aria-label={`Findings for the ${team} team`}>
          {listed.map((finding, index) => (
            <li key={`${finding.path}:${finding.code}:${index}`} className="text-[11px]">
              {finding.stage !== null ? (
                <button
                  type="button"
                  className="text-left hover:underline focus-visible:underline"
                  onClick={() => onSelectStage(finding.stage as string)}
                >
                  <FindingText finding={finding} />
                </button>
              ) : (
                <FindingText finding={finding} />
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function FindingText({ finding }: { finding: TeamFinding }) {
  const severity = worstOf([finding]) ?? "warning";
  return (
    <span>
      <span className={severity === "error" ? "text-status-red" : "text-status-orange"}>
        {LABEL[severity]}
      </span>
      {finding.stage !== null && (
        <span className="font-mono text-text-muted"> {finding.stage}</span>
      )}
      <span className="text-text-secondary">: {finding.message}</span>
    </span>
  );
}
