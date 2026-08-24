"""The architecture figure, drawn rather than derived.

Every other figure in this paper is generated from retained per-sample records,
because a figure that disagrees with the text is a defect the build should
catch. This one cannot be: it is a drawing of the system's topology, and the
topology lives in the code rather than in a results file. So it is authored as
a generator instead of by hand in an editor, for two reasons. The coordinates
are computed from a band table, so a box added to one band cannot silently
overlap the next; and the labels sit in one file beside the module paths they
name, so a reader checking the drawing against the source has a list to check.

The diagram doubles as a map of the seven instrument failures. Each is marked at
the boundary it occurred at, because the claim that four crossed a boundary with
another server and three did not is a claim about this topology, and it is
easier to check on a drawing of the topology than in prose.

Fonts are TeX Gyre Termes and DejaVu Sans Mono, the two the document already
embeds, so the conformance check that counts font families still sees two. There
are no logos or icons: third-party marks would put trademarked artwork into a
journal submission, and the drawn glyphs that stood in for them crowded the
titles they sat beside without telling a reader anything the label did not.

Run:  make paper   (or run this file directly)
"""

from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

# The layout below is authored on a 900-unit grid, which is the width the boxes
# were sized against. The canvas is wider than that. In print the figure is
# bound by height rather than width, so the scale is fixed by the height and
# roughly a fifth of the width allowance was going unused; stretching the grid
# horizontally spends it on the gaps between boxes instead, at no cost to the
# type size, which does not scale with the grid.
GRID = 900.0
SX = 1.22
W = round(GRID * SX)
OUT = Path(__file__).resolve().parent / "figures"

INK = "#161616"
RULE = "#8f8f8f"
DET, DET_EDGE = "#e7ebef", "#78868f"
LLM, LLM_EDGE = "#f7ecdf", "#b8874f"
SRV, SRV_EDGE = "#ebe9f3", "#867ea6"
STORE, STORE_EDGE = "#e5eee8", "#749682"
FAIL = "#ac2e22"
BAND = "#f7f7f7"

parts: list[str] = []
add = parts.append

# Band table: (top, height, number, title). Every box position below is written
# relative to a band top, so the one place a vertical rhythm can go wrong is here.
BANDS: dict[str, tuple[float, float, str, str]] = {}
GAP = 9.0
_cursor = [46.0]


def gx(v: float) -> float:
    """Grid x to canvas x."""
    return round(v * SX, 2)


def band(key: str, height: float, n: str, title: str) -> float:
    """Place the next band under the previous one. Tops are never hand-written,
    so a band that grows pushes its neighbours down instead of covering them."""
    top = _cursor[0]
    _cursor[0] = top + height + GAP
    BANDS[key] = (top, height, n, title)
    add(f'<rect class="band" x="16" y="{top}" width="{W - 32}" height="{height}" rx="7"/>')
    add(f'<text class="bandnum" x="32" y="{top + 21}">{n}</text>')
    add(f'<text class="bandtitle" x="{32 + 9 * len(n) + 5}" y="{top + 21}">{escape(title)}</text>')
    return top


def box(x, y, w, h, fill, edge, dashed=False) -> None:
    d = ' stroke-dasharray="5 3"' if dashed else ""
    add(
        f'<rect x="{gx(x)}" y="{y}" width="{gx(w)}" height="{h}" rx="5" '
        f'fill="{fill}" stroke="{edge}"{d}/>'
    )


def label(x, y, s, cls="lbl", anchor="middle") -> None:
    add(f'<text class="{cls}" x="{gx(x)}" y="{y}" text-anchor="{anchor}">{escape(s)}</text>')


def lines(x, y, rows, cls="sub", dy=15.0) -> None:
    for i, r in enumerate(rows):
        label(x, y + i * dy, r, cls)


def arrow(x1, y1, x2, y2, cls="flow") -> None:
    add(f'<path class="{cls}" d="M {gx(x1)} {y1} L {gx(x2)} {y2}" marker-end="url(#ah)"/>')


def path(d_grid: str, cls="flow") -> None:
    """A polyline given as (command, value) pairs on the grid. Horizontal
    coordinates are transformed; vertical ones are not, so a right angle stays
    one."""
    out, i = [], 0
    toks = d_grid.split()
    while i < len(toks):
        c = toks[i]
        if c in ("H",):
            out.append(f"H {gx(float(toks[i + 1]))}")
            i += 2
        elif c in ("V",):
            out.append(f"V {toks[i + 1]}")
            i += 2
        elif c == "M":
            out.append(f"M {gx(float(toks[i + 1]))} {toks[i + 2]}")
            i += 3
        else:
            raise ValueError(c)
    add(f'<path class="{cls}" d="{" ".join(out)}" marker-end="url(#ah)"/>')


def fail(x, y, tag) -> None:
    # The marker is a circle on the canvas, so only its centre is transformed.
    add(f'<circle class="failmark" cx="{gx(x)}" cy="{y}" r="11.5"/>')
    add(f'<text class="failtxt" x="{gx(x)}" y="{y + 4}" text-anchor="middle">{tag}</text>')


# ------------------------------------------------------------ 1. intake
b = band("intake", 72, "1", "Sample intake")
box(300, b + 30, 300, 42, DET, DET_EDGE)
label(450, b + 48, "Windows PE sample")
label(450, b + 64, "resolved by SHA-256 to a family signature", "sub")
box(24, b + 30, 256, 42, DET, DET_EDGE, dashed=True)
label(152, b + 48, "dated cohort", "lbl9")
label(152, b + 64, "stratified by year, digest recorded", "sub")
box(620, b + 30, 256, 42, DET, DET_EDGE, dashed=True)
label(748, b + 48, "MITRE ATT&CK uses set", "lbl9")
label(748, b + 64, "ground truth, scoring only", "sub")

# --------------------------------------------------- 2. evidence acquisition
b = band("eviAcq", 154, "2", "Evidence acquisition, over three protocols")
srv = [
    (
        42,
        "Ghidra MCP",
        "HTTP",
        [
            "headless disassembly",
            "decompile, imports, strings,",
            "call graph, function hashes",
            "165 tools advertised, 20 exposed",
        ],
    ),
    (
        256,
        "CAPEv2 sandbox",
        "MCP",
        [
            "detonation on one Windows guest",
            "reverted between analyses",
            "behavioural JSON, dropped files,",
            "PCAP capture",
        ],
    ),
    (
        470,
        "Network MCP",
        "MCP",
        ["local PCAP inspection", "pcap summary, DNS, HTTP", "no traffic leaves the host"],
    ),
    (
        684,
        "threat-intel MCP",
        "HTTP",
        [
            "VirusTotal, AbuseIPDB, WHOIS",
            "enrichment only, never scored",
            "reputation and registration",
        ],
    ),
]
for x, name, proto, rows in srv:
    box(x, b + 32, 174, 116, SRV, SRV_EDGE)
    label(x + 87, b + 52, name, "lbl9", "middle")
    label(x + 87, b + 67, proto, "tag")
    lines(x + 87, b + 86, rows, "sub", 14.0)
fail(42 + 156, b + 48, "M2")
fail(42 + 156, b + 76, "M3")
fail(256 + 156, b + 48, "M1")

# ------------------------------------------------ 3. deterministic layers
b = band("layer0", 92, "3", "Deterministic evidence layers, Layer 0, no model involved")
det = [
    (36, "YARA", "0.90", "signature match"),
    (176, "tool-artifact", "0.90", "RAT byte markers"),
    (316, "Sigma", "0.55", "log rules"),
    (456, "import-capability", "0.35", "PE import sets"),
    (596, "LOLBin", "0.35", "signed-proxy exec"),
    (736, "network DGA", "0.20", "domain entropy"),
]
for x, name, w, note in det:
    box(x, b + 28, 128, 58, DET, DET_EDGE)
    label(x + 64, b + 46, name, "lbl9")
    label(x + 64, b + 61, f"trust {w}", "tag")
    label(x + 64, b + 77, note, "sub")

# ----------------------------------------------------------- 4. retrieval
b = band("retrieval", 92, "4", "Retrieval and priors")
label(190, b + 21, "Qdrant, BAAI/bge-small-en-v1.5, 384-dim", "tag", "start")
label(868, b + 21, "into every analyst prompt", "tag", "end")
ret = [
    (36, "ATT&CK case-prior RAG", ["nearest past cases", "prime the mapping"]),
    (256, "family-feature RAG", ["family fingerprints", "leakage-free split"]),
    (476, "function-hash attribution", ["normalised opcode hashes", "matched to a corpus"]),
    (696, "hybrid ATT&CK index", ["dense ranks, TF-IDF gates", "assigns every identifier"]),
]
for x, name, rows in ret:
    box(x, b + 28, 168, 58, STORE, STORE_EDGE)
    label(x + 84, b + 46, name, "lbl9")
    lines(x + 84, b + 62, rows, "sub", 14.0)

# ------------------------------------------------------- 5. analysis graph
# The scheduling note rides on the band title rather than sitting between the
# rows: as a free-floating line it was exactly where the fan-in arrow runs, and
# a caption crossed by an arrow reads as neither.
b = band("graph", 206, "5", "Analysis graph, LangGraph StateGraph over one shared state")
label(868, b + 21, "sequential on one local slot; fan-out from START when multi-slot", "tag", "end")
AW = 240.0
ana = [
    (
        42,
        "static analyst",
        "domain weight 0.35",
        [
            "ReAct loop over Ghidra MCP",
            "20-tool curated allowlist",
            "sink-reachability hint injected",
        ],
    ),
    (
        330,
        "dynamic analyst",
        "domain weight 0.45",
        ["ReAct loop over the sandbox", "API calls, injection chains,", "persistence"],
    ),
    (
        618,
        "network analyst",
        "domain weight 0.20",
        ["PCAP or parsed-flow text", "beaconing, DGA, tunnelling"],
    ),
]
for x, name, w, rows in ana:
    box(x, b + 32, AW, 84, LLM, LLM_EDGE)
    label(x + AW / 2, b + 51, name)
    label(x + AW / 2, b + 66, w, "tag")
    lines(x + AW / 2, b + 83, rows, "sub", 14.0)
fail(42 + AW - 20, b + 52, "M4")
for x1, x2 in ((282, 328), (570, 616)):
    arrow(x1, b + 74, x2, b + 74)
    label((x1 + x2) / 2, b + 66, "then", "tag")

# The second row is laid out around the gaps its own labels need: 120 units
# between negotiation and revision for "no consensus", and a return path low
# enough that its caption clears both corners.
box(24, b + 136, 154, 46, DET, DET_EDGE, dashed=True)
label(101, b + 155, "sycophancy detector", "lbl9")
label(101, b + 171, "an echo of a peer, flagged", "sub")
box(250, b + 136, 220, 46, LLM, LLM_EDGE)
label(360, b + 155, "negotiation")
label(360, b + 171, "contradictions, dissent, consensus", "sub")
box(590, b + 136, 220, 46, LLM, LLM_EDGE)
label(700, b + 155, "revision")
label(700, b + 171, "re-run an analyst on the dispute", "sub")
path(f"M 450 {b + 116} V {b + 126} H 360 V {b + 134}")
path(f"M 470 {b + 159} H 588")
label(529, b + 151, "no consensus", "tag")
path(f"M 700 {b + 182} V {b + 194} H 360 V {b + 184}")
label(530, b + 190, "loop until consensus or the cap", "tag")

# -------------------------------------------------------------- 6. cascade
b = band("cascade", 80, "6", "Corroboration cascade, deterministic")
box(150, b + 28, 600, 46, DET, DET_EDGE)
label(450, b + 46, "per-technique weighted confidence over contributing layers")
label(
    450,
    b + 63,
    "cross-layer multiplier 1.00, 1.25, 1.50, 1.75, 1.90 at 1 to 5 independent layers",
    "sub",
)
fail(736, b + 40, "M5")

# ---------------------------------------------------------------- 7. judge
b = band("judge", 76, "7", "Verdict")
box(230, b + 26, 440, 42, LLM, LLM_EDGE)
label(450, b + 44, "judge, give_verdict")
label(450, b + 60, "synthesises the analysts' claims and the cascade block into STIX 2.1", "sub")
fail(656, b + 38, "M7")

# ------------- 8. deterministic post-pass, and the artefact it produces
# Gating and output share one band. They were two, and the height that bought
# was paid for at the other end: the figure is scaled to a measure, so a band
# saved is width gained, and width is what decides whether the smallest label
# is legible on paper.
b = band(
    "post", 94, "8", "Deterministic reconciliation and gating, after the model, and the artefact"
)
post = [
    ("reconciliation step", ["drops unresolvable IDs,", "restores cascade techniques"]),
    ("invalid-ID filter", ["checked against", "the ATT&CK catalogue"]),
    ("confidence cap", ["falsification before", "confidence"]),
    ("STIX integrity pass", ["dangling references,", "malformed objects"]),
    ("STIX 2.1 bundle", ["attack-patterns and", "relationships"]),
    ("report", ["HTML, Markdown and", "PDF renderers"]),
]
BW, BG = 138.0, 6.4
for i, (name, rows) in enumerate(post):
    x = 36 + i * (BW + BG)
    box(x, b + 28, BW, 58, DET, DET_EDGE)
    label(x + BW / 2, b + 46, name, "lbl9")
    lines(x + BW / 2, b + 62, rows, "sub", 14.0)

# ------------------------------------------------------------ 10. substrate
b = band("sub", 90, "9", "Substrate")
box(36, b + 26, 400, 56, SRV, SRV_EDGE)
label(236, b + 44, "local inference")
lines(
    236,
    b + 60,
    [
        "ik_llama.cpp llama-server, Qwen3.6-35B-A3B at IQ3_K_R4",
        "one RTX 5060, hybrid MoE offload, 131,072-token context",
    ],
    "sub",
    13.0,
)
fail(422, b + 38, "M6")
box(464, b + 26, 400, 56, SRV, SRV_EDGE, dashed=True)
label(664, b + 44, "hosted comparison endpoints")
lines(
    664,
    b + 60,
    ["OpenRouter and DashScope, used only for the measured arms;", "never in the production path"],
    "sub",
    13.0,
)

# The vertical spine runs in the gaps between bands only, so it never crosses a
# band title. Each pair is (bottom of one band, top of the next).
for key_a, key_b in [
    ("intake", "eviAcq"),
    ("eviAcq", "layer0"),
    ("layer0", "retrieval"),
    ("retrieval", "graph"),
    ("graph", "cascade"),
    ("cascade", "judge"),
    ("judge", "post"),
    ("post", "sub"),
]:
    ta, ha, *_ = BANDS[key_a]
    tb, *_ = BANDS[key_b]
    arrow(450, ta + ha, 450, tb, "spine")

# Retrieval feeds every analyst prompt rather than the spine. The connectors
# stop at the band edge instead of being routed inside it: a line drawn across a
# band would have to cross that band's own title.
gt = BANDS["graph"][0]
rt, rh, *_ = BANDS["retrieval"]
for x in (150, 750):
    arrow(x, rt + rh, x, gt)

# ------------------------------------------------------------- 11. legend
LEG = _cursor[0] + 8
add(f'<rect class="band" x="16" y="{LEG - 18}" width="{W - 32}" height="34" rx="7"/>')
for x, fill, edge, name in [
    (36, DET, DET_EDGE, "deterministic"),
    (206, LLM, LLM_EDGE, "language model"),
    (386, SRV, SRV_EDGE, "another server"),
    (566, STORE, STORE_EDGE, "retrieval store"),
]:
    add(
        f'<rect x="{gx(x)}" y="{LEG - 8}" width="16" height="11" rx="2" '
        f'fill="{fill}" stroke="{edge}"/>'
    )
    label(x + 23, LEG + 2, name, "sub", "start")
fail(722, LEG - 2, "Mn")
label(740, LEG + 2, "instrument failure", "sub", "start")

H = LEG + 28

STYLE = f"""
  text {{ font-family: 'TeX Gyre Termes', 'Nimbus Roman', 'Times New Roman', serif; fill: {INK}; }}
  .lbl  {{ font-size: 17.5px; }}
  .lbl9 {{ font-size: 15.5px; }}
  .sub  {{ font-size: 13.5px; fill: #3a3a3a; }}
  .tag  {{ font-family: 'DejaVu Sans Mono', monospace; font-size: 11.5px; fill: #575757; }}
  .band {{ fill: {BAND}; stroke: #e0e0e0; stroke-width: 1; }}
  .bandnum   {{ font-family: 'DejaVu Sans Mono', monospace; font-size: 13.5px; fill: #757575; }}
  .bandtitle {{ font-size: 15px; fill: #464646; }}
  rect  {{ stroke-width: 1.1; }}
  .flow  {{ fill: none; stroke: {RULE}; stroke-width: 1.3; }}
  .spine {{ fill: none; stroke: {RULE}; stroke-width: 1.9; }}
  .failmark {{ fill: #ffffff; stroke: {FAIL}; stroke-width: 1.6; }}
  .failtxt  {{ font-family: 'DejaVu Sans Mono', monospace; font-size: 11px; fill: {FAIL}; }}
"""

svg = (
    f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">\n'
    f"<style>{STYLE}</style>\n"
    '<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" '
    'markerHeight="6" orient="auto-start-reverse">'
    f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{RULE}"/></marker></defs>\n'
    f'<rect width="{W}" height="{H}" fill="#ffffff"/>\n' + "\n".join(parts) + "\n</svg>\n"
)

OUT.mkdir(parents=True, exist_ok=True)
svg_path = OUT / "fig5-architecture.svg"
svg_path.write_text(svg, encoding="utf-8")
print(f"wrote {svg_path.name}  ({len(svg):,} bytes, {len(parts)} elements, {W}x{H})")

pdf_path = OUT / "fig5-architecture.pdf"
try:
    import cairosvg
except ImportError:  # pragma: no cover - the SVG is the portable deliverable
    print("cairosvg not installed; SVG written, PDF not built")
else:
    cairosvg.svg2pdf(url=str(svg_path), write_to=str(pdf_path))
    print(f"wrote {pdf_path.name}  ({pdf_path.stat().st_size:,} bytes)")
