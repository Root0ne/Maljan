import { describe, expect, it } from "vitest";

import type { TeamFinding, TeamGraph } from "@/types/settings";
import {
  NODE_HEIGHT,
  NODE_WIDTH,
  clip,
  nodeSummary,
  placeGraph,
  stageCardId,
  teamFindings,
  worstOf,
} from "../teamGraph";

function finding(over: Partial<TeamFinding> = {}): TeamFinding {
  return {
    severity: "error",
    code: "unknown_agent",
    message: "profile 'mine', stage 'a': unknown agent 'ghost'",
    team: "mine",
    stage: "a",
    field: "agents",
    agent: null,
    path: "core.agents.profiles.mine.stages.a.agents",
    ...over,
  };
}

function node(key: string, row: number, column = 0, over: Partial<TeamGraph["nodes"][0]> = {}) {
  return {
    key,
    label: "",
    kind: "analysis",
    agents: ["static"],
    when: "",
    reads: "findings",
    mode: "sequential",
    row,
    column,
    ...over,
  };
}

/* triage_pack feeds two analysis stages side by side, both feed the verdict. */
const FORK: TeamGraph = {
  nodes: [
    node("triage_pack", 0, 0, { kind: "triage", agents: [] }),
    node("a", 1, 0),
    node("b", 1, 1, { when: "has_pcap" }),
    node("v", 2, 0, { kind: "verdict", agents: ["judge"] }),
  ],
  edges: [
    { source: "triage_pack", target: "a", implicit: false, legal: true },
    { source: "triage_pack", target: "b", implicit: false, legal: true },
    { source: "a", target: "v", implicit: false, legal: true },
    { source: "b", target: "v", implicit: false, legal: true },
  ],
  rows: 3,
  columns: 2,
};

describe("placing the layout the API sent", () => {
  it("puts a stage in the row and column it was given, and nowhere else", () => {
    const placed = placeGraph(FORK, [], "mine");
    const a = placed.nodes.find((n) => n.key === "a")!;
    const b = placed.nodes.find((n) => n.key === "b")!;
    expect(a.y).toBe(b.y);
    expect(b.x).toBeGreaterThan(a.x + NODE_WIDTH);
    const v = placed.nodes.find((n) => n.key === "v")!;
    expect(v.y).toBeGreaterThan(a.y + NODE_HEIGHT);
  });

  it("is wide enough for every column and tall enough for every row", () => {
    const placed = placeGraph(FORK, [], "mine");
    for (const n of placed.nodes) {
      expect(n.x + NODE_WIDTH).toBeLessThanOrEqual(placed.width);
      expect(n.y + NODE_HEIGHT).toBeLessThanOrEqual(placed.height);
    }
  });

  it("draws an edge downward from the stage run first to the stage that waits", () => {
    const placed = placeGraph(FORK, [], "mine");
    const edge = placed.edges.find((e) => e.source === "a" && e.target === "v")!;
    const [, , y1] = edge.d.split(" ");
    const y2 = edge.d.split(" ").at(-1)!;
    expect(Number(y2)).toBeGreaterThan(Number(y1));
  });

  it("drops an edge that names a stage the layout does not have", () => {
    const graph = { ...FORK, edges: [...FORK.edges, { source: "ghost", target: "a", implicit: false, legal: true }] };
    expect(placeGraph(graph, [], "mine").edges).toHaveLength(FORK.edges.length);
  });

  it("bends an illegal edge out to the right of the boxes", () => {
    const graph: TeamGraph = {
      nodes: [node("a", 0), node("v", 1, 0, { kind: "verdict" })],
      edges: [
        { source: "a", target: "v", implicit: false, legal: true },
        { source: "v", target: "a", implicit: false, legal: false },
      ],
      rows: 2,
      columns: 1,
    };
    const placed = placeGraph(graph, [], "mine");
    const illegal = placed.edges.find((e) => !e.legal)!;
    const numbers = illegal.d.match(/[\d.]+/g)!.map(Number);
    expect(Math.max(...numbers)).toBeGreaterThan(NODE_WIDTH);
    expect(Math.max(...numbers)).toBeLessThanOrEqual(placed.width);
  });
});

describe("findings on the stage they concern", () => {
  it("hands each stage its own findings and its worst severity", () => {
    const findings = [
      finding(),
      finding({ severity: "warning", code: "never_runs", stage: "b", message: "never" }),
      finding({ team: "other" }),
    ];
    const placed = placeGraph(FORK, findings, "mine");
    const byKey = Object.fromEntries(placed.nodes.map((n) => [n.key, n]));
    expect(byKey.a.worst).toBe("error");
    expect(byKey.b.worst).toBe("warning");
    expect(byKey.v.worst).toBeNull();
    expect(byKey.a.findings).toHaveLength(1);
  });

  it("keeps a finding about the whole team off every stage", () => {
    const whole = finding({ stage: null, field: null, code: "builtin", message: "built in" });
    const split = teamFindings([whole, finding()], "mine");
    expect(split.team).toEqual([whole]);
    expect(split.byStage.get("a")).toHaveLength(1);
  });

  it("ranks an error above a warning", () => {
    expect(worstOf([finding({ severity: "warning" }), finding()])).toBe("error");
    expect(worstOf([finding({ severity: "warning" })])).toBe("warning");
    expect(worstOf([])).toBeNull();
  });
});

describe("the words behind the picture", () => {
  it("says what a stage is, when it runs and what is wrong with it", () => {
    const placed = placeGraph(FORK, [finding({ stage: "b" }), finding({ stage: "b", severity: "warning" })], "mine");
    const b = placed.nodes.find((n) => n.key === "b")!;
    expect(nodeSummary(b)).toBe("b, analysis stage; agents static; runs when has_pcap; 1 error; 1 warning");
  });

  it("cuts a long label with an ellipsis and leaves a short one alone", () => {
    expect(clip("short", 10)).toBe("short");
    expect(clip("a_rather_long_stage_key", 10)).toBe("a_rather_…");
  });

  it("gives every stage card of every team its own id", () => {
    expect(stageCardId("mine", "a")).not.toBe(stageCardId("mine_a", ""));
    expect(stageCardId("mine", "Bad Key")).not.toMatch(/\s/);
  });
});
