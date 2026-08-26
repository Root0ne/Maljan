"""Deterministic report figures — real inline SVG from real data (Phase 5).

The corpus reports are figure-heavy. The local model cannot produce decompiler
screenshots, so we generate **real charts/diagrams deterministically** from the
report's own data (no fabrication, no screenshots): a process tree, an ATT&CK
tactic matrix, a section-entropy chart, a network graph, an infection-chain
flow, and Ghidra code listings as ``<pre>`` text figures.

Each ``build_*`` returns a ``Figure`` or ``None`` (omit when the data is
absent). SVG uses only primitives (rect/line/text) so it renders identically in
the browser and in WeasyPrint (Phase 6), and is theme-neutral (uses
``currentColor`` / explicit greys so it works on the light PDF surface).
``build_figures(report)`` assembles every applicable figure in report order.
"""

from __future__ import annotations

from html import escape

from maljan.reporting.models import Figure, MalwareReport, ProcessNode

# Kill-chain tactic order for the ATT&CK matrix / infection chain.
_TACTIC_ORDER: list[tuple[str, str]] = [
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Priv. Esc."),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command & Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

_INK = "#1b1f24"
_MUTED = "#57606a"
_ACCENT = "#0969da"
_DANGER = "#cf222e"
_WARN = "#bc4c00"
_LINE = "#d0d7de"


def _svg(width: int, height: int, body: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" font-family="Inter, Arial, sans-serif" font-size="12">{body}</svg>'
    )


def _text(
    x: int, y: int, s: str, *, fill: str = _INK, size: int = 12, weight: str = "normal"
) -> str:
    return (
        f'<text x="{x}" y="{y}" fill="{fill}" font-size="{size}" '
        f'font-weight="{weight}">{escape(s)}</text>'
    )


def _rect(
    x: int, y: int, w: int, h: int, *, fill: str = "#fff", stroke: str = _LINE, rx: int = 4
) -> str:
    return (
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
        f'fill="{fill}" stroke="{stroke}"/>'
    )


# ---------------------------------------------------------------------------
# Process tree
# ---------------------------------------------------------------------------


def build_process_tree(report: MalwareReport) -> Figure | None:
    dyn = report.dynamic
    if not dyn or not dyn.process_tree:
        return None
    rows: list[tuple[int, ProcessNode]] = []

    def _walk(node: ProcessNode, depth: int) -> None:
        rows.append((depth, node))
        for child in node.children[:12]:
            _walk(child, depth + 1)

    for root in dyn.process_tree[:6]:
        _walk(root, 0)
    rows = rows[:40]
    row_h = 24
    height = max(40, len(rows) * row_h + 20)
    parts: list[str] = []
    for i, (depth, node) in enumerate(rows):
        y = 20 + i * row_h
        x = 12 + depth * 26
        injected = " ⤳ injects" if node.injected_into else ""
        label = f"{node.name or 'proc'} (pid {node.pid}){injected}"
        if depth > 0:
            parts.append(
                f'<line x1="{x - 13}" y1="{y - 6}" x2="{x - 3}" y2="{y - 6}" stroke="{_LINE}"/>'
            )
        dot = _DANGER if node.injected_into else _ACCENT
        parts.append(f'<circle cx="{x}" cy="{y - 6}" r="3" fill="{dot}"/>')
        parts.append(_text(x + 8, y - 2, label, fill=_INK))
    return Figure(
        id="fig-process-tree",
        caption="Process tree (sandbox execution)",
        kind="process_tree",
        content=_svg(720, height, "".join(parts)),
        legend="Red node = process injection target.",
    )


# ---------------------------------------------------------------------------
# ATT&CK tactic matrix
# ---------------------------------------------------------------------------


def build_attack_matrix(report: MalwareReport) -> Figure | None:
    if not report.ttp_mappings:
        return None
    by_tactic: dict[str, list[str]] = {}
    for m in report.ttp_mappings:
        tac = m.tactic or ""
        by_tactic.setdefault(tac, [])
        tid = m.technique_id or ""
        if tid and tid not in by_tactic[tac]:
            by_tactic[tac].append(tid)
    cols = [(tid, name) for tid, name in _TACTIC_ORDER if tid in by_tactic]
    if not cols:
        return None
    col_w = 118
    gap = 8
    width = len(cols) * (col_w + gap) + gap
    max_rows = max((len(by_tactic[t]) for t, _ in cols), default=0)
    height = 60 + max_rows * 22 + 16
    parts: list[str] = []
    for i, (tid, name) in enumerate(cols):
        x = gap + i * (col_w + gap)
        parts.append(_rect(x, 12, col_w, 34, fill="#f6f8fa"))
        parts.append(_text(x + 8, 32, name, fill=_INK, size=11, weight="bold"))
        for j, tech in enumerate(by_tactic[tid][:8]):
            ty = 52 + j * 22
            parts.append(_rect(x, ty, col_w, 18, fill="#ddf4ff", stroke=_ACCENT))
            parts.append(_text(x + 6, ty + 13, tech, fill=_ACCENT, size=10))
    return Figure(
        id="fig-attack-matrix",
        caption="MITRE ATT&CK tactic coverage",
        kind="attack_matrix",
        content=_svg(width, height, "".join(parts)),
        legend=None,
    )


# ---------------------------------------------------------------------------
# Section entropy chart
# ---------------------------------------------------------------------------


def build_entropy_chart(report: MalwareReport) -> Figure | None:
    if not report.static or not report.static.sections:
        return None
    sections = report.static.sections[:12]
    bar_h = 22
    height = 40 + len(sections) * (bar_h + 8)
    width = 620
    axis_x = 130
    max_w = width - axis_x - 60
    parts: list[str] = [_text(12, 20, "Section entropy (0–8, ≥7 suspicious)", fill=_MUTED, size=11)]
    for i, sec in enumerate(sections):
        y = 34 + i * (bar_h + 8)
        ent = max(0.0, min(8.0, float(sec.entropy or 0.0)))
        w = int(max_w * ent / 8.0)
        color = _DANGER if ent >= 7.0 else (_WARN if ent >= 6.0 else _ACCENT)
        parts.append(_text(12, y + 15, (sec.name or "?")[:16], fill=_INK, size=11))
        parts.append(_rect(axis_x, y, max_w, bar_h, fill="#f6f8fa", stroke=_LINE))
        parts.append(_rect(axis_x, y, max(2, w), bar_h, fill=color, stroke="none", rx=0))
        parts.append(_text(axis_x + max_w + 8, y + 15, f"{ent:.2f}", fill=_MUTED, size=11))
    return Figure(
        id="fig-entropy",
        caption="PE section entropy",
        kind="entropy_chart",
        content=_svg(width, height, "".join(parts)),
        legend="Red ≥ 7.0 (packed/encrypted), orange ≥ 6.0.",
    )


# ---------------------------------------------------------------------------
# Network graph
# ---------------------------------------------------------------------------


def build_network_graph(report: MalwareReport) -> Figure | None:
    net = report.network
    if not net or not (net.domains or net.ips):
        return None
    endpoints: list[tuple[str, bool]] = []
    for d in net.domains[:8]:
        endpoints.append((d.fqdn, bool(getattr(d, "is_suspicious", False))))
    for ip in net.ips[:8]:
        endpoints.append((f"{ip.address}:{ip.port}" if ip.port else ip.address, True))
    endpoints = endpoints[:12]
    if not endpoints:
        return None
    row_h = 30
    height = max(80, len(endpoints) * row_h + 30)
    width = 620
    cx, cy = 90, height // 2
    parts: list[str] = [
        f'<circle cx="{cx}" cy="{cy}" r="26" fill="#ddf4ff" stroke="{_ACCENT}"/>',
        _text(cx - 20, cy + 4, "sample", fill=_ACCENT, size=11, weight="bold"),
    ]
    from maljan.reporting.builder import defang

    for i, (label, suspicious) in enumerate(endpoints):
        y = 20 + i * row_h
        bx = 300
        parts.append(f'<line x1="{cx + 26}" y1="{cy}" x2="{bx}" y2="{y + 11}" stroke="{_LINE}"/>')
        col = _DANGER if suspicious else _MUTED
        parts.append(_rect(bx, y, 300, 22, fill="#fff", stroke=col))
        parts.append(_text(bx + 8, y + 15, defang(label)[:44], fill=_INK, size=11))
    return Figure(
        id="fig-network",
        caption="Network endpoints (C2 / resolved)",
        kind="network_graph",
        content=_svg(width, height, "".join(parts)),
        legend="Red border = flagged suspicious.",
    )


# ---------------------------------------------------------------------------
# Infection-chain flow
# ---------------------------------------------------------------------------


def build_infection_chain(report: MalwareReport) -> Figure | None:
    present = {m.tactic for m in report.ttp_mappings if m.tactic}
    stages = [(tid, name) for tid, name in _TACTIC_ORDER if tid in present]
    if len(stages) < 2:
        return None
    box_w, box_h, gap = 118, 40, 26
    per_row = 4
    width = per_row * box_w + (per_row - 1) * gap + 24
    rows = (len(stages) + per_row - 1) // per_row
    height = rows * (box_h + gap) + 12
    parts: list[str] = []
    for i, (_tid, name) in enumerate(stages):
        r, c = divmod(i, per_row)
        x = 12 + c * (box_w + gap)
        y = 12 + r * (box_h + gap)
        parts.append(_rect(x, y, box_w, box_h, fill="#f6f8fa", stroke=_ACCENT))
        parts.append(_text(x + 8, y + 24, name, fill=_INK, size=11))
        if i < len(stages) - 1 and c < per_row - 1:
            ax = x + box_w
            parts.append(
                f'<line x1="{ax}" y1="{y + box_h // 2}" x2="{ax + gap}" y2="{y + box_h // 2}" '
                f'stroke="{_MUTED}" marker-end="url(#arrow)"/>'
            )
    defs = (
        f'<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" '
        f'orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="{_MUTED}"/></marker></defs>'
    )
    return Figure(
        id="fig-infection-chain",
        caption="Kill-chain progression (observed tactics)",
        kind="infection_chain",
        content=_svg(width, height, defs + "".join(parts)),
        legend=None,
    )


# ---------------------------------------------------------------------------
# Ghidra code listings (text figures)
# ---------------------------------------------------------------------------


def build_code_listings(report: MalwareReport) -> list[Figure]:
    figs: list[Figure] = []
    ev = report.technical_evidence or {}
    seq = 0
    for outputs in ev.values():
        for o in outputs or []:
            if o.get("tool_name") != "decompile_function":
                continue
            body = str(o.get("output") or "").strip()
            if not body:
                continue
            sym = str(o.get("symbol") or "").strip() or "function"
            figs.append(
                Figure(
                    id=f"fig-listing-{seq}",
                    caption=f"Decompiled {sym}",
                    kind="code_listing",
                    content=f'<pre class="listing">{escape(body[:4000])}</pre>',
                    legend=None,
                )
            )
            seq += 1
            if seq >= 4:
                return figs
    return figs


def build_figures(report: MalwareReport) -> list[Figure]:
    """Assemble every applicable figure in report order. Never raises."""
    figs: list[Figure] = []
    for builder in (
        build_infection_chain,
        build_attack_matrix,
        build_process_tree,
        build_entropy_chart,
        build_network_graph,
    ):
        try:
            fig = builder(report)
        except Exception:  # noqa: BLE001
            fig = None
        if fig is not None:
            figs.append(fig)
    try:
        figs.extend(build_code_listings(report))
    except Exception:  # noqa: BLE001
        pass
    return figs
