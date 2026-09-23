"use client";

import { useMemo, useRef, useState, type KeyboardEvent } from "react";

import EvidenceChips from "@/components/analysis/EvidenceChips";
import JsonNode from "@/components/analysis/JsonTree";
import { downloadBlob, downloadObject } from "@/lib/report-utils";
import {
  colourForType,
  formatConfidence,
  layoutGraph,
  legendLayout,
  readStixGraph,
  resolveCssVars,
  shortLabel,
  type GraphEdge,
  type GraphNode,
  type Layout,
  type Point,
  type StixGraph,
} from "./stixGraph";

const RADIUS = 9;
/** Edge labels are drawn on every edge up to this many, and past it only on
 *  the edges of the selected or focused node, where they can still be read. */
const LABEL_ALL_EDGES_UP_TO = 120;
const MIN_ZOOM = 0.2;
const MAX_ZOOM = 3;

type Selection = { kind: "node"; id: string } | { kind: "edge"; key: string } | null;

const BUTTON =
  "px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted disabled:opacity-50";

function activate(event: KeyboardEvent, run: () => void) {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    run();
  }
}

/** The path one edge draws: straight for a single edge between two nodes,
 *  bowed for the second and later ones so parallel edges stay apart, and a
 *  small loop for an object related to itself. */
function edgeGeometry(s: Point, t: Point, bend: number) {
  if (s.x === t.x && s.y === t.y) {
    const r = RADIUS * 2.2;
    return {
      d: `M ${s.x - RADIUS * 0.6} ${s.y - RADIUS * 0.8} C ${s.x - r} ${s.y - r * 2.2}, ${s.x + r} ${s.y - r * 2.2}, ${s.x + RADIUS * 0.6} ${s.y - RADIUS * 0.8}`,
      label: { x: s.x, y: s.y - r * 1.9 },
    };
  }
  const dx = t.x - s.x;
  const dy = t.y - s.y;
  const len = Math.hypot(dx, dy) || 1;
  const nx = -dy / len;
  const ny = dx / len;
  const c = { x: (s.x + t.x) / 2 + nx * bend, y: (s.y + t.y) / 2 + ny * bend };
  // Start and end on the circles' rims, aimed at the control point, so the
  // arrowhead sits on the target's edge rather than under it.
  const toward = (from: Point, to: Point, by: number) => {
    const ex = to.x - from.x;
    const ey = to.y - from.y;
    const el = Math.hypot(ex, ey) || 1;
    return { x: from.x + (ex / el) * by, y: from.y + (ey / el) * by };
  };
  const a = toward(s, c, RADIUS);
  const b = toward(t, c, RADIUS + 3);
  return {
    d: `M ${a.x} ${a.y} Q ${c.x} ${c.y} ${b.x} ${b.y}`,
    label: { x: (a.x + 2 * c.x + b.x) / 4, y: (a.y + 2 * c.y + b.y) / 4 },
  };
}

/** How far each edge bows: parallel edges between one pair fan out evenly. */
function bends(edges: GraphEdge[]): Map<string, number> {
  const byPair = new Map<string, GraphEdge[]>();
  for (const e of edges) {
    const pair = [e.source, e.target].sort().join("|");
    const list = byPair.get(pair) ?? [];
    list.push(e);
    byPair.set(pair, list);
  }
  const out = new Map<string, number>();
  for (const list of byPair.values()) {
    list.forEach((e, i) => {
      const offset = (i - (list.length - 1) / 2) * 22;
      // Bow direction is taken against one fixed orientation of the pair, so
      // two opposite edges between the same nodes still fan apart.
      const flipped = e.source > e.target ? -1 : 1;
      out.set(e.key, offset * flipped);
    });
  }
  return out;
}

function Legend({ nodes }: { nodes: GraphNode[] }) {
  const types = [...new Set(nodes.map((n) => n.type))].sort();
  if (types.length === 0) return null;
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-text-secondary" aria-label="Colour by STIX type">
      {types.map((type) => (
        <li key={type} className="inline-flex items-center gap-1.5">
          <svg width="10" height="10" aria-hidden="true">
            <circle cx="5" cy="5" r="5" style={{ fill: colourForType(type) }} />
          </svg>
          <span className="font-mono">{type}</span>
        </li>
      ))}
    </ul>
  );
}

function Detail({
  graph,
  selection,
  onSelect,
}: {
  graph: StixGraph;
  selection: Selection;
  onSelect: (s: Selection) => void;
}) {
  const nodeById = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph]);
  if (!selection) {
    return (
      <p className="text-xs text-text-muted">
        Select a node or an edge to read its STIX object and the evidence it cites.
      </p>
    );
  }
  const name = (id: string) => nodeById.get(id)?.label ?? id;

  if (selection.kind === "node") {
    const node = nodeById.get(selection.id);
    if (!node) return null;
    const touching = graph.edges.filter((e) => e.source === node.id || e.target === node.id);
    return (
      <div className="space-y-3">
        <div>
          <p className="text-[11px] font-mono text-text-muted">{node.type}</p>
          <h3 className="text-sm font-semibold text-text-primary break-words">{node.label}</h3>
          <p className="text-[11px] font-mono text-text-muted break-all">{node.id}</p>
        </div>
        <EvidenceLine ids={node.evidenceIds} />
        <div>
          <p className="text-xs text-text-secondary mb-1">
            {touching.length === 0
              ? "No relationship in this bundle names this object."
              : `Relationships (${touching.length})`}
          </p>
          <ul className="space-y-0.5">
            {touching.map((e) => (
              <li key={e.key}>
                <button
                  type="button"
                  onClick={() => onSelect({ kind: "edge", key: e.key })}
                  className="text-left text-xs text-accent-strong hover:underline break-words"
                >
                  {e.source === node.id
                    ? `${e.label} → ${name(e.target)}`
                    : `${name(e.source)} → ${e.label}`}
                </button>
              </li>
            ))}
          </ul>
        </div>
        <ObjectJson object={node.object} />
      </div>
    );
  }

  const edge = graph.edges.find((e) => e.key === selection.key);
  if (!edge) return null;
  return (
    <div className="space-y-3">
      <div>
        <p className="text-[11px] font-mono text-text-muted">{edge.type}</p>
        <h3 className="text-sm font-semibold text-text-primary break-words">
          <button
            type="button"
            onClick={() => onSelect({ kind: "node", id: edge.source })}
            className="text-accent-strong hover:underline text-left"
          >
            {name(edge.source)}
          </button>{" "}
          <span className="font-mono text-text-secondary">{edge.label}</span>{" "}
          <button
            type="button"
            onClick={() => onSelect({ kind: "node", id: edge.target })}
            className="text-accent-strong hover:underline text-left"
          >
            {name(edge.target)}
          </button>
        </h3>
        <p className="text-[11px] font-mono text-text-muted break-all">{edge.id}</p>
      </div>
      <p className="text-xs text-text-secondary">
        {edge.confidence
          ? `Confidence ${formatConfidence(edge.confidence)} (${edge.confidence.property})`
          : "The bundle states no confidence for this edge."}
      </p>
      <EvidenceLine ids={edge.evidenceIds} />
      <ObjectJson object={edge.object} />
    </div>
  );
}

function EvidenceLine({ ids }: { ids: string[] }) {
  return ids.length > 0 ? (
    <div className="text-xs text-text-secondary">
      <span className="mr-1.5">Evidence</span>
      <EvidenceChips ids={ids} />
    </div>
  ) : (
    <p className="text-xs text-text-muted">This object carries no evidence-ledger ids.</p>
  );
}

function ObjectJson({ object }: { object: unknown }) {
  return (
    <div className="p-3 rounded border border-border bg-bg-deep font-mono text-[11px] leading-relaxed overflow-x-auto">
      <JsonNode data={object} />
    </div>
  );
}

/** The same nodes and edges as rows: the screen-reader view of the graph and
 *  the view a large bundle opens on. Without `onSelect` the rows are plain
 *  text, which is how the hidden copy beside a drawn graph is printed: a
 *  control nobody can see is not left in the tab order. */
function GraphTable({
  graph,
  onSelect,
}: {
  graph: StixGraph;
  onSelect?: (s: Selection) => void;
}) {
  const nodeById = new Map(graph.nodes.map((n) => [n.id, n]));
  const name = (id: string) => nodeById.get(id)?.label ?? id;
  const degree = new Map<string, number>();
  for (const e of graph.edges) {
    degree.set(e.source, (degree.get(e.source) ?? 0) + 1);
    if (e.target !== e.source) degree.set(e.target, (degree.get(e.target) ?? 0) + 1);
  }
  const th = "px-2 py-1.5 text-left font-medium text-text-secondary";
  const td = "px-2 py-1 align-top";
  return (
    <div className="space-y-5 text-xs">
      <div className="overflow-x-auto">
        <table className="w-full border-collapse">
          <caption className="text-left text-xs font-semibold text-text-primary pb-1.5">
            Objects ({graph.nodes.length})
          </caption>
          <thead>
            <tr className="border-b border-border">
              <th scope="col" className={th}>Object</th>
              <th scope="col" className={th}>STIX type</th>
              <th scope="col" className={th}>Relationships</th>
              <th scope="col" className={th}>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {graph.nodes.map((n) => (
              <tr key={n.id} className="border-b border-border-light">
                <td className={`${td} break-words`}>
                  {onSelect ? (
                    <button
                      type="button"
                      onClick={() => onSelect({ kind: "node", id: n.id })}
                      className="text-left text-accent-strong hover:underline break-words"
                    >
                      {n.label}
                    </button>
                  ) : (
                    n.label
                  )}
                </td>
                <td className={`${td} font-mono text-text-secondary`}>{n.type}</td>
                <td className={`${td} text-text-secondary`}>{degree.get(n.id) ?? 0}</td>
                <td className={td}>
                  {n.evidenceIds.length > 0 && onSelect ? (
                    <EvidenceChips ids={n.evidenceIds} />
                  ) : (
                    <span className="text-text-muted">
                      {n.evidenceIds.length > 0 ? n.evidenceIds.join(", ") : "none"}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full border-collapse">
          <caption className="text-left text-xs font-semibold text-text-primary pb-1.5">
            Relationships ({graph.edges.length})
          </caption>
          <thead>
            <tr className="border-b border-border">
              <th scope="col" className={th}>Source</th>
              <th scope="col" className={th}>Relationship</th>
              <th scope="col" className={th}>Target</th>
              <th scope="col" className={th}>Confidence</th>
              <th scope="col" className={th}>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {graph.edges.length === 0 && (
              <tr>
                <td colSpan={5} className={`${td} text-text-muted`}>
                  This bundle holds no relationship.
                </td>
              </tr>
            )}
            {graph.edges.map((e) => (
              <tr key={e.key} className="border-b border-border-light">
                <td className={`${td} break-words text-text-primary`}>{name(e.source)}</td>
                <td className={`${td} font-mono`}>
                  {onSelect ? (
                    <button
                      type="button"
                      onClick={() => onSelect({ kind: "edge", key: e.key })}
                      className="font-mono text-accent-strong hover:underline"
                    >
                      {e.label}
                    </button>
                  ) : (
                    e.label
                  )}
                </td>
                <td className={`${td} break-words text-text-primary`}>{name(e.target)}</td>
                <td className={`${td} text-text-secondary`}>
                  {e.confidence ? formatConfidence(e.confidence) : "not stated"}
                </td>
                <td className={td}>
                  {e.evidenceIds.length > 0 && onSelect ? (
                    <EvidenceChips ids={e.evidenceIds} />
                  ) : (
                    <span className="text-text-muted">
                      {e.evidenceIds.length > 0 ? e.evidenceIds.join(", ") : "none"}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {graph.notDrawn.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <caption className="text-left text-xs font-semibold text-text-primary pb-1.5">
              In the bundle, not drawn ({graph.notDrawn.length})
            </caption>
            <thead>
              <tr className="border-b border-border">
                <th scope="col" className={th}>Object</th>
                <th scope="col" className={th}>STIX type</th>
                <th scope="col" className={th}>Why</th>
              </tr>
            </thead>
            <tbody>
              {graph.notDrawn.map((o, i) => (
                <tr key={`${o.id}#${i}`} className="border-b border-border-light">
                  <td className={`${td} break-words text-text-primary`}>{o.label}</td>
                  <td className={`${td} font-mono text-text-secondary`}>{o.type}</td>
                  <td className={`${td} text-text-secondary`}>{o.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const SVG_NS = "http://www.w3.org/2000/svg";

/** The plain look of an element the selection or focus restyles. */
const PLAIN_EDGE = "fill: none; stroke: var(--border); stroke-width: 1.25";
const PLAIN_EDGE_LABEL = "fill: var(--text-secondary); stroke: var(--bg-surface); stroke-width: 3";

/**
 * The drawing as a standalone SVG: no selection or focus on it, the page's
 * colours written in, and a legend above the graph, because a saved picture
 * has no panel beside it to carry the key.
 */
function exportMarkup(svg: SVGSVGElement, layout: Layout, types: string[]): string {
  const clone = svg.cloneNode(true) as SVGSVGElement;
  clone.querySelectorAll('[data-export="omit"]').forEach((el) => el.remove());
  clone.querySelectorAll("[data-plain-style]").forEach((el) => {
    el.setAttribute("style", el.getAttribute("data-plain-style") ?? "");
    el.removeAttribute("data-plain-style");
  });
  clone.querySelectorAll("[tabindex], [role], [aria-label], [aria-pressed]").forEach((el) => {
    for (const name of ["tabindex", "role", "aria-label", "aria-pressed", "class"]) {
      el.removeAttribute(name);
    }
  });

  const legend = legendLayout(types, layout.width);
  const width = Math.ceil(layout.width);
  const height = Math.ceil(layout.height + legend.height);
  const body = document.createElementNS(SVG_NS, "g");
  body.setAttribute("transform", `translate(0 ${legend.height})`);
  for (const child of Array.from(clone.childNodes)) {
    if (child.nodeName !== "defs") body.appendChild(child);
  }
  const key = document.createElementNS(SVG_NS, "g");
  for (const item of legend.items) {
    const swatch = document.createElementNS(SVG_NS, "circle");
    swatch.setAttribute("cx", String(item.x + 5));
    swatch.setAttribute("cy", String(item.y));
    swatch.setAttribute("r", "5");
    swatch.setAttribute("style", `fill: ${colourForType(item.type)}`);
    const name = document.createElementNS(SVG_NS, "text");
    name.setAttribute("x", String(item.x + 14));
    name.setAttribute("y", String(item.y));
    name.setAttribute("dominant-baseline", "middle");
    name.setAttribute("font-size", "11");
    name.setAttribute("style", "fill: var(--text-secondary)");
    name.textContent = item.type;
    key.append(swatch, name);
  }
  const bg = document.createElementNS(SVG_NS, "rect");
  bg.setAttribute("width", "100%");
  bg.setAttribute("height", "100%");
  bg.setAttribute("style", "fill: var(--bg-surface)");
  clone.append(bg, key, body);

  clone.setAttribute("xmlns", SVG_NS);
  clone.setAttribute("width", String(width));
  clone.setAttribute("height", String(height));
  clone.setAttribute("viewBox", `0 0 ${width} ${height}`);
  for (const name of ["class", "style", "role", "aria-label"]) clone.removeAttribute(name);
  const root = getComputedStyle(document.documentElement);
  return resolveCssVars(new XMLSerializer().serializeToString(clone), (name) =>
    root.getPropertyValue(name),
  );
}

function GraphCanvas({
  graph,
  selection,
  onSelect,
}: {
  graph: StixGraph;
  selection: Selection;
  onSelect: (s: Selection) => void;
}) {
  const layout = useMemo(() => layoutGraph(graph.nodes, graph.edges), [graph]);
  const bend = useMemo(() => bends(graph.edges), [graph]);
  const [zoom, setZoom] = useState<number | "fit">("fit");
  const [focused, setFocused] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const boxRef = useRef<HTMLDivElement>(null);

  const selectedNode = selection?.kind === "node" ? selection.id : null;
  const selectedEdge = selection?.kind === "edge" ? selection.key : null;
  const lit = selectedNode ?? focused;
  const labelAll = graph.edges.length <= LABEL_ALL_EDGES_UP_TO;

  const currentScale = () => {
    if (zoom !== "fit") return zoom;
    const box = boxRef.current?.clientWidth ?? layout.width;
    return Math.min(1, box / layout.width);
  };
  const zoomBy = (factor: number) =>
    setZoom(Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, currentScale() * factor)));

  const types = graph.nodes.map((n) => n.type);
  const saveSvg = () => {
    if (!svgRef.current) return;
    downloadBlob(exportMarkup(svgRef.current, layout, types), "maljan-stix-graph.svg", "image/svg+xml");
  };

  const savePng = () => {
    if (!svgRef.current) return;
    const markup = exportMarkup(svgRef.current, layout, types);
    const size = legendLayout(types, layout.width).height;
    const url = URL.createObjectURL(new Blob([markup], { type: "image/svg+xml" }));
    const image = new Image();
    image.onload = () => {
      const scale = 2;
      const canvas = document.createElement("canvas");
      canvas.width = Math.ceil(layout.width * scale);
      canvas.height = Math.ceil((layout.height + size) * scale);
      const ctx = canvas.getContext("2d");
      if (!ctx) {
        URL.revokeObjectURL(url);
        setExportError("This browser gave no canvas to draw the PNG on; the SVG export still works.");
        return;
      }
      ctx.scale(scale, scale);
      ctx.drawImage(image, 0, 0);
      URL.revokeObjectURL(url);
      canvas.toBlob((blob) => {
        if (blob) {
          setExportError(null);
          downloadObject(blob, "maljan-stix-graph.png");
        } else {
          setExportError("The PNG could not be drawn; the SVG export still works.");
        }
      }, "image/png");
    };
    image.onerror = () => {
      URL.revokeObjectURL(url);
      setExportError("The PNG could not be drawn; the SVG export still works.");
    };
    image.src = url;
  };

  const sized =
    zoom === "fit"
      ? { width: "100%" as const, height: undefined }
      : { width: layout.width * zoom, height: layout.height * zoom };

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className={BUTTON} onClick={() => zoomBy(1 / 1.25)} aria-label="Zoom out">
          −
        </button>
        <button type="button" className={BUTTON} onClick={() => zoomBy(1.25)} aria-label="Zoom in">
          +
        </button>
        <button
          type="button"
          className={BUTTON}
          onClick={() => setZoom("fit")}
          aria-pressed={zoom === "fit"}
        >
          Fit
        </button>
        <span className="flex-1" />
        <button type="button" className={BUTTON} onClick={saveSvg}>
          Export SVG
        </button>
        <button type="button" className={BUTTON} onClick={savePng}>
          Export PNG
        </button>
      </div>
      {exportError && (
        <p role="alert" className="text-xs text-status-red">
          {exportError}
        </p>
      )}
      <Legend nodes={graph.nodes} />
      <div ref={boxRef} className="max-h-[560px] overflow-auto rounded border border-border bg-bg-surface">
        <svg
          ref={svgRef}
          viewBox={`0 0 ${layout.width} ${layout.height}`}
          width={sized.width}
          height={sized.height}
          // Fit shrinks a wide graph to the panel and never enlarges a small
          // one past the size it was laid out at.
          style={zoom === "fit" ? { maxWidth: layout.width } : undefined}
          role="group"
          aria-label={`Relationship graph: ${graph.nodes.length} objects, ${graph.edges.length} edges. The tables below list the same.`}
          fontFamily="ui-sans-serif, system-ui, sans-serif"
          className="block"
        >
          <defs>
            <marker
              id="stix-graph-arrow"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerWidth="7"
              markerHeight="7"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" style={{ fill: "var(--text-muted)" }} />
            </marker>
          </defs>
          <g>
            {graph.edges.map((e) => {
              const s = layout.positions.get(e.source);
              const t = layout.positions.get(e.target);
              if (!s || !t) return null;
              const geo = edgeGeometry(s, t, bend.get(e.key) ?? 0);
              const on = selectedEdge === e.key;
              const near = lit !== null && (e.source === lit || e.target === lit);
              const showLabel = labelAll || on || near;
              const text = e.confidence ? `${e.label} · ${formatConfidence(e.confidence)}` : e.label;
              return (
                <g key={e.key} onClick={() => onSelect({ kind: "edge", key: e.key })} className="cursor-pointer">
                  <title>{`${e.label}${e.confidence ? `, confidence ${formatConfidence(e.confidence)}` : ""}`}</title>
                  <path
                    d={geo.d}
                    data-export="omit"
                    style={{ fill: "none", stroke: "transparent", strokeWidth: 10 }}
                  />
                  <path
                    d={geo.d}
                    markerEnd="url(#stix-graph-arrow)"
                    data-plain-style={PLAIN_EDGE}
                    style={{
                      fill: "none",
                      stroke: on ? "var(--accent)" : near ? "var(--text-secondary)" : "var(--border)",
                      strokeWidth: on ? 2.5 : 1.25,
                    }}
                  />
                  {showLabel && (
                    <text
                      x={geo.label.x}
                      y={geo.label.y}
                      textAnchor="middle"
                      dominantBaseline="middle"
                      fontSize={10}
                      paintOrder="stroke"
                      data-plain-style={PLAIN_EDGE_LABEL}
                      // Drawn only because of the selection: not in a saved picture.
                      data-export={labelAll ? undefined : "omit"}
                      style={{
                        fill: on ? "var(--text-primary)" : "var(--text-secondary)",
                        stroke: "var(--bg-surface)",
                        strokeWidth: 3,
                      }}
                    >
                      {text}
                    </text>
                  )}
                </g>
              );
            })}
          </g>
          <g>
            {graph.nodes.map((n) => {
              const p = layout.positions.get(n.id);
              if (!p) return null;
              const on = selectedNode === n.id;
              const hasFocus = focused === n.id;
              return (
                <g
                  key={n.id}
                  tabIndex={0}
                  role="button"
                  aria-pressed={on}
                  aria-label={`${n.type}: ${n.label}`}
                  onClick={() => onSelect({ kind: "node", id: n.id })}
                  onKeyDown={(event) => activate(event, () => onSelect({ kind: "node", id: n.id }))}
                  onFocus={() => setFocused(n.id)}
                  onBlur={() => setFocused((f) => (f === n.id ? null : f))}
                  className="cursor-pointer focus:outline-none"
                >
                  <title>{`${n.type}: ${n.label}`}</title>
                  {(on || hasFocus) && (
                    <circle
                      data-export="omit"
                      cx={p.x}
                      cy={p.y}
                      r={RADIUS + 4}
                      style={{ fill: "none", stroke: "var(--accent)", strokeWidth: 2 }}
                    />
                  )}
                  <circle
                    cx={p.x}
                    cy={p.y}
                    r={RADIUS}
                    style={{ fill: colourForType(n.type), stroke: "var(--bg-surface)", strokeWidth: 1.5 }}
                  />
                  <text
                    x={p.x}
                    y={p.y + RADIUS + 12}
                    textAnchor="middle"
                    fontSize={11}
                    paintOrder="stroke"
                    style={{ fill: "var(--text-primary)", stroke: "var(--bg-surface)", strokeWidth: 3 }}
                  >
                    {shortLabel(n.label)}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>
      </div>
    </div>
  );
}

/**
 * The run's STIX bundle as a node-link graph, or as the tables that list the
 * same nodes and edges. `showGraph` is the panel's choice; the tables are
 * always in the page, visible when the graph is not and read by a screen
 * reader when it is.
 */
export default function StixGraphView({
  bundle,
  showGraph,
}: {
  bundle: unknown;
  showGraph: boolean;
}) {
  const graph = useMemo(() => readStixGraph(bundle), [bundle]);
  const [selection, setSelection] = useState<Selection>(null);

  if (graph.objectCount === 0) {
    return <p className="text-xs text-text-muted">This bundle holds no STIX objects to draw.</p>;
  }

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
      <div className="min-w-0 space-y-3">
        {showGraph && <GraphCanvas graph={graph} selection={selection} onSelect={setSelection} />}
        <div className={showGraph ? "sr-only" : ""}>
          <GraphTable graph={graph} onSelect={showGraph ? undefined : setSelection} />
        </div>
      </div>
      <aside aria-label="Selected STIX object" className="min-w-0">
        <Detail graph={graph} selection={selection} onSelect={setSelection} />
      </aside>
    </div>
  );
}
