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
embeds, so the conformance check that counts font families still sees two.
Third-party logos are deliberately not used: of the eleven tools named here only
two ship a mark anywhere in this repository, and fetching the rest would put
trademarked artwork into a journal submission for no gain in legibility. Each
tool carries a drawn glyph instead.

Run:  make paper   (or run this file directly)
"""

from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

W = 900
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
    add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="5" fill="{fill}" stroke="{edge}"{d}/>')


def label(x, y, s, cls="lbl", anchor="middle") -> None:
    add(f'<text class="{cls}" x="{x}" y="{y}" text-anchor="{anchor}">{escape(s)}</text>')


def lines(x, y, rows, cls="sub", dy=14.0) -> None:
    for i, r in enumerate(rows):
        label(x, y + i * dy, r, cls)


def arrow(x1, y1, x2, y2, cls="flow") -> None:
    add(f'<path class="{cls}" d="M {x1} {y1} L {x2} {y2}" marker-end="url(#ah)"/>')


def fail(x, y, tag) -> None:
    add(f'<circle class="failmark" cx="{x}" cy="{y}" r="11.5"/>')
    add(f'<text class="failtxt" x="{x}" y="{y + 4}" text-anchor="middle">{tag}</text>')


def glyph(x, y, body) -> None:
    add(f'<g class="ico" transform="translate({x},{y})">{body}</g>')


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
CHIP = (
    '<rect x="0" y="0" width="15" height="11" rx="1.5"/>'
    '<path d="M-4 3 h4 M-4 8 h4 M15 3 h4 M15 8 h4"/>'
)
PLAY = '<rect x="0" y="0" width="17" height="11" rx="1.5"/><path d="M6 3 l5 2.5 l-5 2.5 z"/>'
WAVE = '<path d="M0 8 q4 -8 8 0 t8 0"/><path d="M0 3.5 q4 -6.5 8 0 t8 0" opacity="0.45"/>'
SHIELD = '<path d="M8 0 l8 3 v4.5 q0 4.5 -8 6.5 q-8 -2 -8 -6.5 v-4.5 z"/>'
srv = [
    (
        36,
        CHIP,
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
        254,
        PLAY,
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
        472,
        WAVE,
        "Network MCP",
        "MCP",
        ["local PCAP inspection", "pcap summary, DNS, HTTP", "no traffic leaves the host"],
    ),
    (
        690,
        SHIELD,
        "threat-intel MCP",
        "HTTP",
        [
            "VirusTotal, AbuseIPDB, WHOIS",
            "enrichment only, never scored",
            "reputation and registration",
        ],
    ),
]
for x, ico, name, proto, rows in srv:
    box(x, b + 26, 174, 122, SRV, SRV_EDGE)
    # The glyph sits in the corner rather than beside the title, so the text can
    # be centred on the box itself: centring it around the glyph instead pushed
    # the widest line four units past the right edge.
    glyph(x + 11, b + 36, ico)
    label(x + 87, b + 47, name, "lbl9", "middle")
    label(x + 87, b + 62, proto, "tag")
    lines(x + 87, b + 80, rows, "sub", 13.0)
fail(36 + 160, b + 38, "M2")
fail(36 + 160, b + 64, "M3")
fail(254 + 160, b + 38, "M1")

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
    lines(x + 84, b + 62, rows, "sub", 13.0)

# ------------------------------------------------------- 5. analysis graph
b = band("graph", 214, "5", "Analysis graph, LangGraph StateGraph over one shared state")
ana = [
    (
        52,
        "static analyst",
        "domain weight 0.35",
        [
            "ReAct loop over Ghidra MCP",
            "20-tool curated allowlist",
            "sink-reachability hint injected",
        ],
    ),
    (
        322,
        "dynamic analyst",
        "domain weight 0.45",
        ["ReAct loop over the sandbox", "API calls, injection chains,", "persistence"],
    ),
    (
        592,
        "network analyst",
        "domain weight 0.20",
        ["PCAP or parsed-flow text", "beaconing, DGA, tunnelling"],
    ),
]
for x, name, w, rows in ana:
    box(x, b + 28, 232, 86, LLM, LLM_EDGE)
    label(x + 116, b + 47, name)
    label(x + 116, b + 62, w, "tag")
    lines(x + 116, b + 79, rows, "sub", 13.0)
fail(52 + 218, b + 40, "M4")
arrow(284, b + 71, 320, b + 71)
arrow(554, b + 71, 590, b + 71)
label(302, b + 63, "then", "tag")
label(572, b + 63, "then", "tag")
label(
    450,
    b + 130,
    "sequential on one local slot; fan-out from START when the endpoint is multi-slot",
    "note",
)
box(232, b + 144, 200, 44, LLM, LLM_EDGE)
label(332, b + 162, "negotiation")
label(332, b + 178, "contradictions, dissent, consensus", "sub")
box(482, b + 144, 200, 44, LLM, LLM_EDGE)
label(582, b + 162, "revision")
label(582, b + 178, "re-run an analyst on the dispute", "sub")
arrow(332, b + 116, 332, b + 142)
add(f'<path class="flow" d="M 432 {b + 160} H 480" marker-end="url(#ah)"/>')
label(456, b + 150, "no consensus", "tag")
# the loop returns underneath the two nodes, so nothing crosses the note above
add(f'<path class="flow" d="M 582 {b + 188} V {b + 205} H 352 V {b + 190}" marker-end="url(#ah)"/>')
label(467, b + 201, "loop until consensus or the cap", "tag")
box(700, b + 144, 164, 44, DET, DET_EDGE, dashed=True)
label(782, b + 162, "sycophancy detector", "lbl9")
label(782, b + 178, "an echo of a peer, flagged", "sub")

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
    lines(x + BW / 2, b + 62, rows, "sub", 13.0)

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
        f'<rect x="{x}" y="{LEG - 8}" width="16" height="11" rx="2" fill="{fill}" stroke="{edge}"/>'
    )
    label(x + 23, LEG + 2, name, "sub", "start")
fail(722, LEG - 2, "Mn")
label(740, LEG + 2, "instrument failure", "sub", "start")

H = LEG + 28

STYLE = f"""
  text {{ font-family: 'TeX Gyre Termes', 'Nimbus Roman', 'Times New Roman', serif; fill: {INK}; }}
  .lbl  {{ font-size: 16px; }}
  .lbl9 {{ font-size: 14.5px; }}
  .sub  {{ font-size: 12.5px; fill: #3a3a3a; }}
  .note {{ font-size: 12.5px; fill: #3a3a3a; font-style: italic; }}
  .tag  {{ font-family: 'DejaVu Sans Mono', monospace; font-size: 10.5px; fill: #575757; }}
  .band {{ fill: {BAND}; stroke: #e0e0e0; stroke-width: 1; }}
  .bandnum   {{ font-family: 'DejaVu Sans Mono', monospace; font-size: 12.5px; fill: #757575; }}
  .bandtitle {{ font-size: 14px; fill: #464646; }}
  rect  {{ stroke-width: 1.1; }}
  .flow  {{ fill: none; stroke: {RULE}; stroke-width: 1.3; }}
  .spine {{ fill: none; stroke: {RULE}; stroke-width: 1.9; }}
  .ico   {{ fill: none; stroke: {INK}; stroke-width: 1.25; }}
  .failmark {{ fill: #ffffff; stroke: {FAIL}; stroke-width: 1.6; }}
  .failtxt  {{ font-family: 'DejaVu Sans Mono', monospace; font-size: 10.5px; fill: {FAIL}; }}
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
