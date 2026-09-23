/**
 * A run's STIX bundle read as nodes and edges, and nothing more.
 *
 * The graph is a second way of printing the bundle the export serves, so every
 * node, edge and label here is something the bundle states. An object with no
 * relationship is still a node; a relationship is an edge labelled with its
 * own `relationship_type`; a confidence is printed only when the bundle holds
 * one on the 0–1 scale the platform writes (`x_maljan_confidence`) or on the
 * standard's 0–100 scale (`confidence`), and never filled in. Where the nodes
 * sit is presentation: the layout below places them so that edges are short
 * and nodes do not overlap, and says nothing about the objects.
 *
 * What the reader does not draw it still lists: a container or commentary
 * object (report, note, opinion, grouping, identity, marking) that no
 * relationship names, and a relationship whose end the bundle does not hold.
 * The table view prints both, so the graph and the table account for every
 * object the bundle carries.
 */

export type StixObject = Record<string, unknown> & { id: string; type: string };

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  /** Evidence-ledger ids the object carries under one of its own properties. */
  evidenceIds: string[];
  object: StixObject;
}

/** A confidence exactly as the bundle states it, with the scale it is on. */
export interface StatedConfidence {
  value: number;
  /** `x_maljan_confidence` is 0–1; the standard's `confidence` is 0–100. */
  property: "x_maljan_confidence" | "confidence";
}

export interface GraphEdge {
  /** Unique per drawn edge: a sighting with two places is two edges. */
  key: string;
  /** The id of the relationship or sighting object the edge draws. */
  id: string;
  type: "relationship" | "sighting";
  label: string;
  source: string;
  target: string;
  confidence: StatedConfidence | null;
  evidenceIds: string[];
  object: StixObject;
}

export interface NotDrawn {
  id: string;
  type: string;
  label: string;
  reason: string;
  object: StixObject;
}

export interface StixGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** Objects the bundle carries that no node or edge draws, and why. */
  notDrawn: NotDrawn[];
  /** How many objects the bundle holds, the count the size rule reads. */
  objectCount: number;
}

/** Above this many bundle objects the panel opens on the table. */
export const GRAPH_FIRST_LIMIT = 300;

const EDGE_TYPES: ReadonlySet<string> = new Set(["relationship", "sighting"]);

/**
 * Objects that hold, describe or mark other objects rather than being one of
 * the things a reader follows. They become nodes only when a relationship
 * names them; otherwise the table lists them under "not drawn".
 */
export const CONTAINER_TYPES: ReadonlySet<string> = new Set([
  "report",
  "note",
  "opinion",
  "grouping",
  "identity",
  "marking-definition",
  "extension-definition",
  "language-content",
]);

const EVIDENCE_ID = /^ev_[0-9]+$/;

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function isStixObject(value: unknown): value is StixObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const obj = value as Record<string, unknown>;
  return text(obj.id).length > 0 && text(obj.type).length > 0;
}

/** The bundle's objects, from the export's `{objects: [...]}` shape. */
export function bundleObjects(bundle: unknown): StixObject[] {
  if (!bundle || typeof bundle !== "object") return [];
  const objects = (bundle as Record<string, unknown>).objects;
  if (!Array.isArray(objects)) return [];
  return objects.filter(isStixObject);
}

/** The property the export writes an object's ledger ids under. */
export const EVIDENCE_REFS_PROPERTY = "x_maljan_evidence_refs";

/**
 * The ledger ids an object carries: the `ev_` ids in the export's
 * `x_maljan_evidence_refs`, which it writes from the run's record and only
 * where the record ties the object to entries. No other property is read, and
 * an id in a description or a pattern stays text.
 */
export function evidenceIdsOf(obj: Record<string, unknown>): string[] {
  const value = obj[EVIDENCE_REFS_PROPERTY];
  const found: string[] = [];
  for (const v of Array.isArray(value) ? value : []) {
    const id = text(v);
    if (EVIDENCE_ID.test(id) && !found.includes(id)) found.push(id);
  }
  return found;
}

function attackId(obj: Record<string, unknown>): string {
  const refs = obj.external_references;
  if (!Array.isArray(refs)) return "";
  for (const ref of refs) {
    if (!ref || typeof ref !== "object") continue;
    const r = ref as Record<string, unknown>;
    if (text(r.source_name) === "mitre-attack" && text(r.external_id)) return text(r.external_id);
  }
  return "";
}

function firstHash(obj: Record<string, unknown>): string {
  const hashes = obj.hashes;
  if (!hashes || typeof hashes !== "object") return "";
  for (const [alg, value] of Object.entries(hashes as Record<string, unknown>)) {
    if (text(value)) return `${alg} ${text(value)}`;
  }
  return "";
}

/** What the object calls itself, in the order the standard's own names go. */
export function labelOf(obj: StixObject): string {
  if (obj.type === "attack-pattern") {
    const tid = attackId(obj);
    const name = text(obj.name);
    if (tid && name) return `${tid} ${name}`;
    if (tid || name) return tid || name;
  }
  if (obj.type === "process") {
    const pid = typeof obj.pid === "number" ? `pid ${obj.pid}` : "";
    const cmd = text(obj.command_line);
    if (cmd || pid) return [pid, cmd].filter(Boolean).join(" ");
  }
  return (
    text(obj.name) ||
    text(obj.value) ||
    firstHash(obj) ||
    text(obj.pattern) ||
    text(obj.abstract) ||
    obj.id
  );
}

/**
 * The relationship's confidence when the bundle states one on its scale.
 *
 * The platform's own property is 0–1 and the standard's is an integer 0–100;
 * a value off its scale, a word, or nothing at all is no number, and the edge
 * then prints none. The object's JSON still shows whatever it holds.
 */
export function statedConfidence(obj: Record<string, unknown>): StatedConfidence | null {
  const own = obj.x_maljan_confidence;
  if (typeof own === "number" || (typeof own === "string" && own.trim() !== "")) {
    const n = Number(own);
    if (Number.isFinite(n) && n >= 0 && n <= 1) return { value: n, property: "x_maljan_confidence" };
  }
  const std = obj.confidence;
  if (typeof std === "number" && Number.isInteger(std) && std >= 0 && std <= 100) {
    return { value: std, property: "confidence" };
  }
  return null;
}

export function formatConfidence(c: StatedConfidence): string {
  return c.property === "confidence" ? `${c.value}/100` : c.value.toFixed(2);
}

function refs(value: unknown): string[] {
  return Array.isArray(value) ? value.map(text).filter(Boolean) : [];
}

/** Read the bundle into what the graph draws and what it lists beside it. */
export function readStixGraph(bundle: unknown): StixGraph {
  const objects = bundleObjects(bundle);
  const byId = new Map<string, StixObject>();
  for (const obj of objects) if (!byId.has(obj.id)) byId.set(obj.id, obj);

  const notDrawn: NotDrawn[] = [];
  const edges: GraphEdge[] = [];
  const named = new Set<string>();

  const unresolved = (obj: StixObject, missing: string[]) =>
    notDrawn.push({
      id: obj.id,
      type: obj.type,
      label: text(obj.relationship_type) || obj.type,
      reason: `names ${missing.join(", ")}, which this bundle does not hold`,
      object: obj,
    });

  for (const obj of objects) {
    if (!EDGE_TYPES.has(obj.type)) continue;
    if (obj.type === "relationship") {
      const source = text(obj.source_ref);
      const target = text(obj.target_ref);
      const missing = [source, target].filter((ref) => !byId.has(ref));
      if (missing.length > 0) {
        unresolved(obj, missing.map((m) => m || "an empty ref"));
        continue;
      }
      named.add(source);
      named.add(target);
      edges.push({
        key: obj.id,
        id: obj.id,
        type: "relationship",
        label: text(obj.relationship_type) || "relationship",
        source,
        target,
        confidence: statedConfidence(obj),
        evidenceIds: evidenceIdsOf(obj),
        object: obj,
      });
      continue;
    }
    // A sighting: what was sighted, drawn to each place it was sighted and
    // each observation the sighting cites, under the object's own type.
    const source = text(obj.sighting_of_ref);
    const targets = [...refs(obj.where_sighted_refs), ...refs(obj.observed_data_refs)];
    const missing = targets.filter((ref) => !byId.has(ref));
    if (!source || !byId.has(source) || targets.length === 0) {
      notDrawn.push({
        id: obj.id,
        type: obj.type,
        label: obj.type,
        reason: !source
          ? "names no sighted object"
          : !byId.has(source)
            ? `names ${source}, which this bundle does not hold`
            : "names no place or observation it was sighted in",
        object: obj,
      });
      continue;
    }
    targets.forEach((target, i) => {
      if (!byId.has(target)) return;
      named.add(source);
      named.add(target);
      edges.push({
        key: `${obj.id}#${i}`,
        id: obj.id,
        type: "sighting",
        label: "sighting",
        source,
        target,
        confidence: statedConfidence(obj),
        evidenceIds: evidenceIdsOf(obj),
        object: obj,
      });
    });
    if (missing.length > 0) unresolved(obj, missing);
  }

  const nodes: GraphNode[] = [];
  const seen = new Set<string>();
  for (const obj of objects) {
    if (EDGE_TYPES.has(obj.type) || seen.has(obj.id)) continue;
    seen.add(obj.id);
    if (CONTAINER_TYPES.has(obj.type) && !named.has(obj.id)) {
      notDrawn.push({
        id: obj.id,
        type: obj.type,
        label: labelOf(obj),
        reason: "holds, describes or marks other objects and no relationship names it",
        object: obj,
      });
      continue;
    }
    nodes.push({
      id: obj.id,
      type: obj.type,
      label: labelOf(obj),
      evidenceIds: evidenceIdsOf(obj),
      object: obj,
    });
  }

  return { nodes, edges, notDrawn, objectCount: objects.length };
}

/* ── Colour ─────────────────────────────────────────────────────────────── */

/**
 * One flat token per STIX type family. The colour says which kind of object a
 * node is, the legend says the same in words, and nothing is coloured by how
 * bad it is.
 */
export function colourForType(type: string): string {
  switch (type) {
    case "malware":
      return "var(--status-red)";
    case "attack-pattern":
      return "var(--status-purple)";
    case "indicator":
      return "var(--status-orange)";
    case "infrastructure":
    case "tool":
    case "campaign":
    case "intrusion-set":
    case "threat-actor":
      return "var(--status-blue)";
    case "file":
    case "domain-name":
    case "ipv4-addr":
    case "ipv6-addr":
    case "url":
    case "process":
    case "mutex":
    case "email-addr":
    case "windows-registry-key":
    case "network-traffic":
    case "directory":
    case "observed-data":
      return "var(--status-green)";
    default:
      return "var(--text-muted)";
  }
}

/* ── Layout ─────────────────────────────────────────────────────────────── */

export interface Point {
  x: number;
  y: number;
}

export interface Layout {
  positions: Map<string, Point>;
  width: number;
  height: number;
}

/**
 * A deterministic force layout: nodes start on a circle in bundle order, repel
 * one another, and each edge pulls its two ends together. The same bundle
 * always lands the same way, so an export taken twice is the same picture.
 */
export function layoutGraph(
  nodes: Pick<GraphNode, "id">[],
  edges: Pick<GraphEdge, "source" | "target">[],
  opts: { iterations?: number; spacing?: number; margin?: number; gravity?: number } = {},
): Layout {
  const n = nodes.length;
  const spacing = opts.spacing ?? 130;
  const margin = opts.margin ?? 80;
  // The pull to the middle is strong enough that an object nobody relates
  // stays among the others instead of being pushed out to the rim, which at
  // 300 objects made the picture ten times wider than the part that relates.
  const gravity = opts.gravity ?? 3;
  const positions = new Map<string, Point>();
  if (n === 0) return { positions, width: 2 * margin, height: 2 * margin };

  const side = spacing * Math.max(2, Math.ceil(Math.sqrt(n)));
  const index = new Map(nodes.map((node, i) => [node.id, i]));
  const xs = new Float64Array(n);
  const ys = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    // A golden-angle spiral: evenly spread, and never two nodes on one point.
    const r = (side / 2) * Math.sqrt((i + 0.5) / n);
    const a = i * 2.399963229728653;
    xs[i] = r * Math.cos(a);
    ys[i] = r * Math.sin(a);
  }

  const links: [number, number][] = [];
  for (const e of edges) {
    const s = index.get(e.source);
    const t = index.get(e.target);
    if (s !== undefined && t !== undefined && s !== t) links.push([s, t]);
  }

  const iterations = opts.iterations ?? (n > 150 ? 180 : 300);
  const k = spacing;
  const dx = new Float64Array(n);
  const dy = new Float64Array(n);
  let temperature = side / 8;
  const cooling = temperature / (iterations + 1);

  for (let step = 0; step < iterations; step++) {
    dx.fill(0);
    dy.fill(0);
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        let ddx = xs[i] - xs[j];
        let ddy = ys[i] - ys[j];
        let d2 = ddx * ddx + ddy * ddy;
        if (d2 < 0.01) {
          ddx = 0.1 * ((i % 7) - 3 || 1);
          ddy = 0.1 * ((j % 5) - 2 || 1);
          d2 = ddx * ddx + ddy * ddy;
        }
        const f = (k * k) / d2;
        dx[i] += ddx * f;
        dy[i] += ddy * f;
        dx[j] -= ddx * f;
        dy[j] -= ddy * f;
      }
    }
    for (const [s, t] of links) {
      const ddx = xs[s] - xs[t];
      const ddy = ys[s] - ys[t];
      const d = Math.sqrt(ddx * ddx + ddy * ddy) || 0.01;
      const f = d / k;
      dx[s] -= ddx * f;
      dy[s] -= ddy * f;
      dx[t] += ddx * f;
      dy[t] += ddy * f;
    }
    // The pull to the middle, which keeps a node nobody relates in the picture.
    for (let i = 0; i < n; i++) {
      dx[i] -= xs[i] * gravity;
      dy[i] -= ys[i] * gravity;
      const len = Math.sqrt(dx[i] * dx[i] + dy[i] * dy[i]) || 1;
      const move = Math.min(len, temperature);
      xs[i] += (dx[i] / len) * move;
      ys[i] += (dy[i] / len) * move;
    }
    temperature = Math.max(temperature - cooling, 1);
  }

  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (let i = 0; i < n; i++) {
    minX = Math.min(minX, xs[i]);
    minY = Math.min(minY, ys[i]);
    maxX = Math.max(maxX, xs[i]);
    maxY = Math.max(maxY, ys[i]);
  }
  nodes.forEach((node, i) => {
    positions.set(node.id, { x: xs[i] - minX + margin, y: ys[i] - minY + margin });
  });
  return {
    positions,
    width: maxX - minX + 2 * margin,
    height: maxY - minY + 2 * margin,
  };
}

/* ── Export ─────────────────────────────────────────────────────────────── */

/**
 * Replace every `var(--token)` in an SVG's markup with the value the page
 * resolves it to, so the saved file draws the same colours with no stylesheet.
 * A token the page does not define is left as written.
 */
export function resolveCssVars(markup: string, lookup: (name: string) => string): string {
  return markup.replace(/var\((--[a-z0-9-]+)\)/gi, (whole, name: string) => {
    const value = lookup(name).trim();
    return value || whole;
  });
}

/** A short label for a node, cut on a character boundary with an ellipsis. */
export function shortLabel(label: string, max = 28): string {
  const chars = Array.from(label);
  return chars.length <= max ? label : `${chars.slice(0, max - 1).join("")}…`;
}
