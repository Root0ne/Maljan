import { describe, expect, it } from "vitest";

import {
  GRAPH_FIRST_LIMIT,
  colourForType,
  evidenceIdsOf,
  formatConfidence,
  labelOf,
  layoutGraph,
  readStixGraph,
  resolveCssVars,
  shortLabel,
  statedConfidence,
  type StixObject,
} from "../stixGraph";

const MALWARE = "malware--b2c3d4e5-f6a7-8901-bcde-f12345678901";
const T1027 = "attack-pattern--6ac001a9-6d00-5a42-b0e2-1a0eb1d8c6e7";
const T1012 = "attack-pattern--40b2a9d1-66c6-59d4-bf4d-4442c79242e9";
const HASH = "indicator--ad3f335a-0631-4bc8-974d-f8e3e1bf266c";
const LONE = "domain-name--0f7e5c1a-2b3c-4d5e-8f90-a1b2c3d4e5f6";
const IDENTITY = "identity--9bd1f32c-b6cc-4e50-910b-a95aa2f3f17a";
const NOTE = "note--0d047eeb-3e2f-4d9c-b938-2a98682513c6";
const REPORT = "report--a26fbafd-60f3-4a48-81a9-e71c94818215";

/** The shape the export stores: the judge's edges with their annotations,
 *  the platform's minted objects, and the note and report around them. */
function exportBundle(extra: StixObject[] = []) {
  return {
    type: "bundle",
    id: "bundle--c05e78f6-f39f-459d-bc03-234d11df4afa",
    spec_version: "2.1",
    objects: [
      { type: "malware", id: MALWARE, name: "sample.exe", is_family: false },
      {
        type: "relationship",
        id: "relationship--c3d4e5f6-a7b8-9012-cdef-123456789012",
        relationship_type: "uses",
        source_ref: MALWARE,
        target_ref: T1027,
        x_maljan_confidence: 0.95,
        x_maljan_evidence_basis: "static",
        x_maljan_contributing_agents: ["static_analyst"],
      },
      { type: "identity", id: IDENTITY, name: "Maljan", identity_class: "system" },
      {
        type: "attack-pattern",
        id: T1027,
        name: "Obfuscated Files or Information",
        external_references: [{ source_name: "mitre-attack", external_id: "T1027" }],
      },
      {
        type: "attack-pattern",
        id: T1012,
        name: "Query Registry",
        external_references: [{ source_name: "mitre-attack", external_id: "T1012" }],
      },
      {
        type: "relationship",
        id: "relationship--b68f0649-8bd7-4a79-b492-9b006921e291",
        relationship_type: "uses",
        source_ref: MALWARE,
        target_ref: T1012,
      },
      {
        type: "indicator",
        id: HASH,
        name: "Sample hash 6091f2589fef",
        pattern: "[file:hashes.'SHA-256' = '6091…']",
        x_maljan_evidence: ["ev_0007"],
      },
      {
        type: "relationship",
        id: "relationship--8dcd029b-1b4c-404c-bc7f-5f5814fe393b",
        relationship_type: "indicates",
        source_ref: HASH,
        target_ref: MALWARE,
      },
      { type: "domain-name", id: LONE, value: "example.test" },
      { type: "note", id: NOTE, abstract: "Malware", content: "…", object_refs: [MALWARE] },
      {
        type: "report",
        id: REPORT,
        name: "Maljan analysis",
        object_refs: [MALWARE, T1027, T1012, HASH, NOTE],
      },
      ...extra,
    ],
  };
}

describe("reading the bundle", () => {
  it("draws every object a reader follows, and every relationship as its own edge", () => {
    const graph = readStixGraph(exportBundle());
    expect(graph.nodes.map((n) => n.id)).toEqual([MALWARE, T1027, T1012, HASH, LONE]);
    expect(graph.edges.map((e) => [e.source, e.label, e.target])).toEqual([
      [MALWARE, "uses", T1027],
      [MALWARE, "uses", T1012],
      [HASH, "indicates", MALWARE],
    ]);
    expect(graph.objectCount).toBe(11);
  });

  it("keeps an object with no relationship as a node", () => {
    const lone = readStixGraph(exportBundle()).nodes.find((n) => n.id === LONE);
    expect(lone?.label).toBe("example.test");
  });

  it("lists the containers nobody relates instead of drawing them, so nothing goes missing", () => {
    const graph = readStixGraph(exportBundle());
    expect(graph.notDrawn.map((o) => o.id).sort()).toEqual([IDENTITY, NOTE, REPORT].sort());
    const accounted = graph.nodes.length + new Set(graph.edges.map((e) => e.id)).size + graph.notDrawn.length;
    expect(accounted).toBe(graph.objectCount);
  });

  it("draws a container once a relationship names it", () => {
    const graph = readStixGraph(
      exportBundle([
        {
          type: "relationship",
          id: "relationship--11111111-1111-4111-8111-111111111111",
          relationship_type: "attributed-to",
          source_ref: MALWARE,
          target_ref: IDENTITY,
        },
      ]),
    );
    expect(graph.nodes.map((n) => n.id)).toContain(IDENTITY);
    expect(graph.notDrawn.map((o) => o.id)).not.toContain(IDENTITY);
  });

  it("lists a relationship whose end the bundle does not hold, and draws no node for it", () => {
    const gone = "attack-pattern--99999999-9999-4999-8999-999999999999";
    const graph = readStixGraph(
      exportBundle([
        {
          type: "relationship",
          id: "relationship--22222222-2222-4222-8222-222222222222",
          relationship_type: "uses",
          source_ref: MALWARE,
          target_ref: gone,
        },
      ]),
    );
    expect(graph.nodes.map((n) => n.id)).not.toContain(gone);
    expect(graph.edges.map((e) => e.target)).not.toContain(gone);
    const row = graph.notDrawn.find((o) => o.id === "relationship--22222222-2222-4222-8222-222222222222");
    expect(row?.reason).toContain(gone);
  });

  it("draws a sighting to each place it names", () => {
    const where = "identity--33333333-3333-4333-8333-333333333333";
    const graph = readStixGraph(
      exportBundle([
        { type: "identity", id: where, name: "Sensor" },
        {
          type: "sighting",
          id: "sighting--44444444-4444-4444-8444-444444444444",
          sighting_of_ref: HASH,
          where_sighted_refs: [where],
        },
      ]),
    );
    const sighting = graph.edges.filter((e) => e.type === "sighting");
    expect(sighting.map((e) => [e.source, e.label, e.target])).toEqual([[HASH, "sighting", where]]);
    expect(graph.nodes.map((n) => n.id)).toContain(where);
  });

  it("reads nothing out of something that is not a bundle", () => {
    for (const value of [null, undefined, {}, { objects: "x" }, [], "bundle"]) {
      expect(readStixGraph(value)).toEqual({ nodes: [], edges: [], notDrawn: [], objectCount: 0 });
    }
  });
});

describe("confidence on an edge", () => {
  it("carries the judge's number when the bundle holds one", () => {
    const edge = readStixGraph(exportBundle()).edges[0];
    expect(edge.confidence).toEqual({ value: 0.95, property: "x_maljan_confidence" });
    expect(formatConfidence(edge.confidence!)).toBe("0.95");
  });

  it("carries none when the bundle holds none, rather than a zero or a half", () => {
    const edges = readStixGraph(exportBundle()).edges;
    expect(edges[1].confidence).toBeNull();
    expect(edges[2].confidence).toBeNull();
  });

  it("reads a word, a value off the scale or an empty string as no number", () => {
    for (const value of ["high", 95, -0.1, "", " ", true, [], {}]) {
      expect(statedConfidence({ x_maljan_confidence: value })).toBeNull();
    }
    expect(statedConfidence({ x_maljan_confidence: "0.8" })).toEqual({
      value: 0.8,
      property: "x_maljan_confidence",
    });
  });

  it("reads the standard's 0–100 integer on its own scale", () => {
    const c = statedConfidence({ confidence: 80 });
    expect(c).toEqual({ value: 80, property: "confidence" });
    expect(formatConfidence(c!)).toBe("80/100");
    expect(statedConfidence({ confidence: 0.8 })).toBeNull();
    expect(statedConfidence({ confidence: 101 })).toBeNull();
  });
});

describe("what a node carries", () => {
  it("names a technique by its ATT&CK id and name", () => {
    const node = readStixGraph(exportBundle()).nodes.find((n) => n.id === T1027);
    expect(node?.label).toBe("T1027 Obfuscated Files or Information");
  });

  it("takes the evidence ids an object carries and nothing that is not one", () => {
    expect(evidenceIdsOf({ x_maljan_evidence: ["ev_0007", "ev_0007", "ev_0012"] })).toEqual([
      "ev_0007",
      "ev_0012",
    ]);
    expect(evidenceIdsOf({ evidence_ids: "ev_0003" })).toEqual(["ev_0003"]);
    expect(evidenceIdsOf({ x_maljan_evidence_basis: "static", description: "ev_0001" })).toEqual([]);
    const hash = readStixGraph(exportBundle()).nodes.find((n) => n.id === HASH);
    expect(hash?.evidenceIds).toEqual(["ev_0007"]);
  });

  it("labels an observable by its value, a file by its name or first hash", () => {
    expect(labelOf({ type: "ipv4-addr", id: "ipv4-addr--1", value: "198.51.100.7" })).toBe("198.51.100.7");
    expect(labelOf({ type: "file", id: "file--1", hashes: { "SHA-256": "abc" } })).toBe("SHA-256 abc");
    expect(labelOf({ type: "file", id: "file--2", name: "a.dll", hashes: { MD5: "x" } })).toBe("a.dll");
    expect(labelOf({ type: "process", id: "process--1", pid: 42, command_line: "cmd /c" })).toBe(
      "pid 42 cmd /c",
    );
    expect(labelOf({ type: "x-custom", id: "x-custom--1" })).toBe("x-custom--1");
  });

  it("colours by type from the console's tokens alone", () => {
    for (const type of ["malware", "attack-pattern", "indicator", "tool", "file", "x-custom"]) {
      expect(colourForType(type)).toMatch(/^var\(--[a-z-]+\)$/);
    }
    expect(colourForType("malware")).not.toBe(colourForType("attack-pattern"));
  });

  it("cuts a long label on a character boundary", () => {
    expect(shortLabel("short")).toBe("short");
    const cut = shortLabel("x".repeat(40), 10);
    expect(Array.from(cut)).toHaveLength(10);
    expect(cut.endsWith("…")).toBe(true);
  });
});

/** A bundle of `size` objects: one malware, then techniques, indicators and
 *  observables in turn, a third of them related to the malware and a few to
 *  one another, and a tail nobody relates. */
function generatedBundle(size: number) {
  const objects: StixObject[] = [{ type: "malware", id: "malware--0", name: "m", is_family: false }];
  const kinds = ["attack-pattern", "indicator", "domain-name", "ipv4-addr", "file"];
  let rel = 0;
  let i = 1;
  while (objects.length < size) {
    const type = kinds[i % kinds.length];
    const id = `${type}--${i}`;
    objects.push({ type, id, name: `${type} ${i}`, value: `v${i}` });
    if (objects.length < size && i % 3 !== 0) {
      objects.push({
        type: "relationship",
        id: `relationship--${rel++}`,
        relationship_type: type === "indicator" ? "indicates" : "uses",
        source_ref: type === "indicator" ? id : "malware--0",
        target_ref: type === "indicator" ? "malware--0" : id,
      });
    }
    if (objects.length < size && i % 7 === 0 && i > 7) {
      objects.push({
        type: "relationship",
        id: `relationship--${rel++}`,
        relationship_type: "related-to",
        source_ref: id,
        target_ref: `${kinds[(i - 5) % kinds.length]}--${i - 5}`,
      });
    }
    i += 1;
  }
  return { type: "bundle", id: "bundle--g", objects };
}

describe("a large bundle", () => {
  it("lays out a bundle at the size limit quickly enough to draw on open", () => {
    const bundle = generatedBundle(GRAPH_FIRST_LIMIT);
    const graph = readStixGraph(bundle);
    expect(graph.objectCount).toBe(GRAPH_FIRST_LIMIT);
    const started = performance.now();
    const layout = layoutGraph(graph.nodes, graph.edges);
    const took = performance.now() - started;
    // Measured at about 40 ms on the development machine; the ceiling leaves
    // room for a slow CI runner and still fails a layout that went quadratic
    // twice over.
    expect(took).toBeLessThan(1500);
    expect(layout.positions.size).toBe(graph.nodes.length);
    for (const p of layout.positions.values()) {
      expect(Number.isFinite(p.x) && Number.isFinite(p.y)).toBe(true);
    }
  });

  it("puts no two nodes on top of each other", () => {
    const graph = readStixGraph(generatedBundle(GRAPH_FIRST_LIMIT));
    const points = [...layoutGraph(graph.nodes, graph.edges).positions.values()];
    let closest = Infinity;
    for (let a = 0; a < points.length; a++) {
      for (let b = a + 1; b < points.length; b++) {
        closest = Math.min(closest, Math.hypot(points[a].x - points[b].x, points[a].y - points[b].y));
      }
    }
    expect(closest).toBeGreaterThan(12);
  });

  it("lands the same bundle the same way every time", () => {
    const graph = readStixGraph(generatedBundle(60));
    const a = layoutGraph(graph.nodes, graph.edges);
    const b = layoutGraph(graph.nodes, graph.edges);
    expect([...a.positions.entries()]).toEqual([...b.positions.entries()]);
  });
});

describe("the saved picture", () => {
  it("writes the page's colours into the markup and leaves an unknown token alone", () => {
    const tokens: Record<string, string> = { "--status-red": " #ff7b72", "--bg-surface": "#161b22" };
    const out = resolveCssVars(
      '<circle fill="var(--status-red)"/><rect fill="var(--bg-surface)"/><g fill="var(--nope)"/>',
      (name) => tokens[name] ?? "",
    );
    expect(out).toBe('<circle fill="#ff7b72"/><rect fill="#161b22"/><g fill="var(--nope)"/>');
  });
});
