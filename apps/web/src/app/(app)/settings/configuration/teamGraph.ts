import type {
  TeamFinding,
  TeamGraph,
  TeamGraphEdge,
  TeamGraphNode,
  TeamLintResult,
} from "@/types/settings";

/**
 * Geometry for the team preview beside the stage editor.
 *
 * Where each stage sits is not decided here. The API lays the team out with
 * `maljan.core.team_layout` — the layout the architecture page's team diagrams
 * are drawn with — and sends a row and a column per stage. This turns those
 * into pixels and attaches each lint finding to the stage it concerns, and it
 * stays in the settings area: nothing outside the team editor draws with it.
 */

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * ``value`` as a lint answer, or null when it is not one.
 *
 * The editor draws from whatever the lint route answers, so an answer of the
 * wrong shape — a proxy's error page, a stub that answers every settings
 * path alike — has to be recognised here rather than dereferenced there.
 */
export function readLintResult(value: unknown): TeamLintResult | null {
  if (!isRecord(value) || !Array.isArray(value.findings) || !isRecord(value.graphs)) return null;
  for (const graph of Object.values(value.graphs)) {
    if (!isRecord(graph) || !Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) return null;
  }
  if (!value.findings.every((f) => isRecord(f) && typeof f.message === "string")) return null;
  return value as unknown as TeamLintResult;
}

export const NODE_WIDTH = 176;
export const NODE_HEIGHT = 54;
const GAP_X = 16;
const GAP_Y = 30;
const PAD = 10;
/** Room on the right for an illegal edge, which bends out past the boxes. */
const BEND = 28;

export type Severity = "error" | "warning";

export interface PlacedNode extends TeamGraphNode {
  x: number;
  y: number;
  findings: TeamFinding[];
  /** The most serious finding on the stage, or null for a clean one. */
  worst: Severity | null;
}

export interface PlacedEdge extends TeamGraphEdge {
  d: string;
}

export interface PlacedGraph {
  width: number;
  height: number;
  nodes: PlacedNode[];
  edges: PlacedEdge[];
}

export function worstOf(findings: TeamFinding[]): Severity | null {
  if (findings.some((f) => f.severity === "error")) return "error";
  if (findings.length > 0) return "warning";
  return null;
}

/** Findings about one team, split into those on a stage and those on the team. */
export function teamFindings(
  findings: TeamFinding[],
  team: string
): { byStage: Map<string, TeamFinding[]>; team: TeamFinding[] } {
  const byStage = new Map<string, TeamFinding[]>();
  const whole: TeamFinding[] = [];
  for (const finding of findings) {
    if (finding.team !== team) continue;
    if (finding.stage === null) {
      whole.push(finding);
      continue;
    }
    byStage.set(finding.stage, [...(byStage.get(finding.stage) ?? []), finding]);
  }
  return { byStage, team: whole };
}

function left(column: number): number {
  return PAD + column * (NODE_WIDTH + GAP_X);
}

function top(row: number): number {
  return PAD + row * (NODE_HEIGHT + GAP_Y);
}

function edgePath(source: TeamGraphNode, target: TeamGraphNode, legal: boolean): string {
  if (!legal) {
    // A dependency on a stage written further down points up the picture; it
    // leaves and enters on the right so it cannot hide behind the boxes.
    const x1 = left(source.column) + NODE_WIDTH;
    const y1 = top(source.row) + NODE_HEIGHT / 2;
    const x2 = left(target.column) + NODE_WIDTH;
    const y2 = top(target.row) + NODE_HEIGHT / 2;
    const bend = Math.max(x1, x2) + BEND - 6;
    return `M ${x1} ${y1} C ${bend} ${y1} ${bend} ${y2} ${x2} ${y2}`;
  }
  const x1 = left(source.column) + NODE_WIDTH / 2;
  const y1 = top(source.row) + NODE_HEIGHT;
  const x2 = left(target.column) + NODE_WIDTH / 2;
  const y2 = top(target.row) - 3;
  const mid = (y1 + y2) / 2;
  return `M ${x1} ${y1} C ${x1} ${mid} ${x2} ${mid} ${x2} ${y2}`;
}

/** The graph in pixels, each stage carrying its own findings. */
export function placeGraph(graph: TeamGraph, findings: TeamFinding[], team: string): PlacedGraph {
  const { byStage } = teamFindings(findings, team);
  const columns = Math.max(graph.columns, 1);
  const rows = Math.max(graph.rows, 1);
  const nodes = graph.nodes.map((node) => {
    const own = byStage.get(node.key) ?? [];
    return { ...node, x: left(node.column), y: top(node.row), findings: own, worst: worstOf(own) };
  });
  const byKey = new Map(graph.nodes.map((node) => [node.key, node]));
  const edges: PlacedEdge[] = [];
  for (const edge of graph.edges) {
    const source = byKey.get(edge.source);
    const target = byKey.get(edge.target);
    if (!source || !target) continue;
    edges.push({ ...edge, d: edgePath(source, target, edge.legal) });
  }
  return {
    width: PAD * 2 + columns * NODE_WIDTH + (columns - 1) * GAP_X + BEND,
    height: PAD * 2 + rows * NODE_HEIGHT + (rows - 1) * GAP_Y,
    nodes,
    edges,
  };
}

/** ``text`` cut to ``max`` characters with an ellipsis, for a fixed-width box. */
export function clip(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, Math.max(max - 1, 0))}…`;
}

function count(n: number, one: string): string {
  return `${n} ${one}${n === 1 ? "" : "s"}`;
}

/** What a screen reader hears for one stage of the preview. */
export function nodeSummary(node: PlacedNode): string {
  const parts = [`${node.key}, ${node.kind} stage`];
  if (node.agents.length) parts.push(`agents ${node.agents.join(", ")}`);
  if (node.when) parts.push(`runs when ${node.when}`);
  const errors = node.findings.filter((f) => f.severity === "error").length;
  const warnings = node.findings.length - errors;
  if (errors) parts.push(count(errors, "error"));
  if (warnings) parts.push(count(warnings, "warning"));
  return parts.join("; ");
}

/** The element id of a stage card, so the preview can move focus to it. */
export function stageCardId(team: string, stage: string): string {
  // A colon cannot appear in a team or stage key, so it cannot collide; a
  // key typed with a space in it is still an id with none.
  return `stage-card:${team}:${stage}`.replace(/\s/g, "_");
}
