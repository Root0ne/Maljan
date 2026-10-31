"""Deterministic report figures — real inline SVG from real data.

The corpus reports are figure-heavy. The local model cannot produce decompiler
screenshots, so we generate **real charts/diagrams deterministically** from the
report's own data (no fabrication, no screenshots): a process tree, an ATT&CK
tactic matrix, a section-entropy chart, a network graph, an infection-chain
flow, and decompiled code listings as ``<pre>`` text figures.

Each ``build_*`` returns a ``Figure`` or ``None`` (omit when the data is
absent). SVG uses only primitives (rect/line/text) so it renders identically in
the browser and in WeasyPrint, and is theme-neutral (uses
``currentColor`` / explicit greys so it works on the light PDF surface).
``build_figures(report)`` assembles every applicable figure in report order.
"""

from __future__ import annotations

from html import escape
from typing import Any

from maljan.core.logger import logger
from maljan.core.undeclared_tools import address_arguments, code_listing, function_key
from maljan.reporting import tool_kinds
from maljan.reporting.dedupe import distinct_processes
from maljan.reporting.defang import defang
from maljan.reporting.models import Figure, MalwareReport, ProcessNode
from maljan.utils.marked_cut import marked_cut

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


# What one figure holds: a drawing, not the record. Whatever a figure leaves
# out its legend counts, and the report's tables and its JSON form carry.
_TREE_ROWS = 40
_NETWORK_ENDPOINTS = 12
_MATRIX_CELLS = 8
_ENTROPY_SECTIONS = 12
_LISTING_CHARS = 4000
_LISTINGS = 4


def _figure_left_out(total: int, shown: int, what: str) -> str:
    """The legend's sentence for what a figure did not draw, or ``""``."""
    rest = int(total) - int(shown)
    if rest <= 0:
        return ""
    return (
        f" {rest:,} more {what} are not drawn; the report's tables and the JSON report "
        "carry every one."
    )


def _text(
    x: int, y: int, s: str, *, fill: str = _INK, size: int = 12, weight: str = "normal"
) -> str:
    return (
        f'<text x="{x}" y="{y}" fill="{fill}" font-size="{size}" '
        f'font-weight="{weight}">{escape(s)}</text>'
    )


def _written(text: str) -> str:
    """A sample's or a model's text for a figure's label, every network value in it defanged."""
    from maljan.reporting.renderers.markdown import _defanged_text

    return _defanged_text(text)


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

    every: list[tuple[int, ProcessNode]] = []

    def _walk(node: ProcessNode, depth: int) -> None:
        every.append((depth, node))
        for child in node.children:
            _walk(child, depth + 1)

    for root in distinct_processes(dyn.process_tree):
        _walk(root, 0)
    # A figure holds forty rows; the rest are counted in its legend.
    rows = every[:_TREE_ROWS]
    row_h = 24
    height = max(40, len(rows) * row_h + 20)
    parts: list[str] = []
    for i, (depth, node) in enumerate(rows):
        y = 20 + i * row_h
        x = 12 + depth * 26
        injected = " ⤳ injects" if node.injected_into else ""
        # The name a sandbox recorded, defanged as the report's text is.
        from maljan.reporting.renderers.markdown import _defanged_text

        label = f"{_defanged_text(node.name or 'proc')} (pid {node.pid}){injected}"
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
        legend="Red node = process injection target."
        + _figure_left_out(len(every), len(rows), "processes"),
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
    # A mapping whose tactic is not one of the twelve columns, or one past a
    # column's eight cells, is not drawn; the legend counts it.
    mapped = sum(len(techniques) for techniques in by_tactic.values())
    drawn = sum(min(len(by_tactic[t]), _MATRIX_CELLS) for t, _ in cols)
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
        for j, tech in enumerate(by_tactic[tid][:_MATRIX_CELLS]):
            ty = 52 + j * 22
            parts.append(_rect(x, ty, col_w, 18, fill="#ddf4ff", stroke=_ACCENT))
            parts.append(_text(x + 6, ty + 13, _written(tech), fill=_ACCENT, size=10))
    return Figure(
        id="fig-attack-matrix",
        caption="MITRE ATT&CK tactic coverage",
        kind="attack_matrix",
        content=_svg(width, height, "".join(parts)),
        legend=_figure_left_out(mapped, drawn, "techniques").strip() or None,
    )


# ---------------------------------------------------------------------------
# Section entropy chart
# ---------------------------------------------------------------------------


def build_entropy_chart(report: MalwareReport) -> Figure | None:
    if not report.static or not report.static.sections:
        return None
    every = report.static.sections
    sections = every[:_ENTROPY_SECTIONS]
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
        parts.append(
            _text(12, y + 15, marked_cut(_written(sec.name or "?"), 16), fill=_INK, size=11)
        )
        parts.append(_rect(axis_x, y, max_w, bar_h, fill="#f6f8fa", stroke=_LINE))
        parts.append(_rect(axis_x, y, max(2, w), bar_h, fill=color, stroke="none", rx=0))
        parts.append(_text(axis_x + max_w + 8, y + 15, f"{ent:.2f}", fill=_MUTED, size=11))
    return Figure(
        id="fig-entropy",
        caption="Section entropy",
        kind="entropy_chart",
        content=_svg(width, height, "".join(parts)),
        legend="Red ≥ 7.0 (packed/encrypted), orange ≥ 6.0. A name ending in … is cut to fit."
        + _figure_left_out(len(every), len(sections), "sections"),
    )


# ---------------------------------------------------------------------------
# Network graph
# ---------------------------------------------------------------------------


def _published_addresses(report: MalwareReport) -> set[str]:
    """The addresses the report publishes as network indicators (the IOC section's set)."""
    from maljan.reporting.detection_signatures import _published_rows
    from maljan.reporting.ledger_projection import value_key

    try:
        return {value_key("ip", row.value) for row in _published_rows(report) if row.kind == "ip"}
    except Exception as exc:  # noqa: BLE001 — a figure is never worth a report
        logger.warning("The published addresses were not read (%s).", type(exc).__name__)
        return set()


def build_network_graph(report: MalwareReport) -> Figure | None:
    from maljan.reporting.ledger_projection import value_key

    net = report.network
    if not net or not (net.domains or net.ips):
        return None
    held = _published_addresses(report) if net.ips else set()
    every: list[tuple[str, bool]] = []
    for d in net.domains:
        every.append((defang(d.fqdn, "domain"), bool(getattr(d, "is_suspicious", False))))
    for ip in net.ips:
        address = defang(ip.address, "ip")
        flagged = bool(getattr(ip, "is_suspicious", False)) or value_key("ip", ip.address) in held
        every.append((f"{address}:{ip.port}" if ip.port else address, flagged))
    # A figure holds twelve endpoints; the rest are counted in its legend.
    endpoints = every[:_NETWORK_ENDPOINTS]
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
    for i, (label, suspicious) in enumerate(endpoints):
        y = 20 + i * row_h
        bx = 300
        parts.append(f'<line x1="{cx + 26}" y1="{cy}" x2="{bx}" y2="{y + 11}" stroke="{_LINE}"/>')
        col = _DANGER if suspicious else _MUTED
        parts.append(_rect(bx, y, 300, 22, fill="#fff", stroke=col))
        parts.append(_text(bx + 8, y + 15, marked_cut(label, 44), fill=_INK, size=11))
    return Figure(
        id="fig-network",
        caption="Network endpoints (observed)",
        kind="network_graph",
        content=_svg(width, height, "".join(parts)),
        legend="Red border = flagged suspicious or published. A label ending in … is cut to fit."
        + _figure_left_out(len(every), len(endpoints), "endpoints"),
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
        caption="Observed tactics in kill-chain order",
        kind="infection_chain",
        content=_svg(width, height, defs + "".join(parts)),
        legend="Tactics are drawn in ATT&CK order, not the order the run observed them.",
    )


def build_execution_flow(report: MalwareReport) -> Figure | None:
    """The report's execution-flow steps as a column of boxes, entry to steady state.

    Drawn when the analyst report is rendered, from the steps the report holds
    (``renderers.analyst.flow_step_labels``, the same labels its Markdown
    diagram carries); ``None`` for fewer than two steps.
    """
    from maljan.reporting.renderers.analyst import flow_step_labels

    labels = flow_step_labels(report)
    if not labels:
        return None
    box_w, box_h, gap = 660, 30, 18
    width = box_w + 24
    height = len(labels) * (box_h + gap) - gap + 24
    parts: list[str] = []
    for i, (label, mark) in enumerate(labels):
        y = 12 + i * (box_h + gap)
        observed = mark == "observed"
        parts.append(
            _rect(12, y, box_w, box_h, fill="#f6f8fa", stroke=_ACCENT if observed else _LINE)
        )
        parts.append(_text(22, y + 19, _written(f"{label} ({mark})"), fill=_INK, size=11))
        if i < len(labels) - 1:
            x = 12 + box_w // 2
            parts.append(
                f'<line x1="{x}" y1="{y + box_h}" x2="{x}" y2="{y + box_h + gap}" '
                f'stroke="{_MUTED}" marker-end="url(#flow-arrow)"/>'
            )
    defs = (
        f'<defs><marker id="flow-arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" '
        f'orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="{_MUTED}"/></marker></defs>'
    )
    return Figure(
        id="fig-execution-flow",
        caption="Execution flow, entry point to steady state",
        kind="execution_flow",
        content=_svg(width, height, defs + "".join(parts)),
        legend="A step a sandbox watched is outlined in blue; every other step is read from "
        "the code. Each box holds its step's first sentence.",
    )


# ---------------------------------------------------------------------------
# Decompiled code listings (text figures), from any decompiler
# ---------------------------------------------------------------------------


def _listed_symbol(output: dict[str, Any], facts: Any) -> str:
    """What a listing's caption names: the call's symbol, else its address argument.

    The address argument is the one the tool declares for the ``address``
    role, else one named for an address (``core.undeclared_tools.
    address_arguments``), as the call gave it. ``function`` when the call
    names neither.
    """
    symbol = str(output.get("symbol") or "").strip()
    if symbol:
        return symbol
    held = output.get("args")
    args: dict[str, Any] = held if isinstance(held, dict) else {}
    for name in address_arguments(facts, tuple(args)):
        value = args.get(name)
        if isinstance(value, str | int) and not isinstance(value, bool) and str(value).strip():
            return str(value).strip()
    return "function"


# The note a listing read from an answer cut for storage carries.
LISTING_CUT_FOR_STORAGE = "The answer was cut for storage; the listing ends where the cut fell."
# The note the last function read of a batch's answer cut for storage carries.
ANSWER_CUT_AFTER_LISTING = (
    "The answer was cut for storage after this function; later functions are not shown."
)


def build_code_listings(report: MalwareReport) -> list[Figure]:
    """The first ``_LISTINGS`` decompiled functions as figures, the rest counted.

    A figure is a drawing of a few functions, not the record: the last one
    drawn says how many more the run decompiled, and the evidence ledger holds
    every listing whole.
    """
    from maljan.core.undeclared_tools import code_parts_read

    with code_parts_read():
        return _build_code_listings(report)


def _build_code_listings(report: MalwareReport) -> list[Figure]:
    """:func:`build_code_listings`, each answer read once (``undeclared_tools.code_parts_read``)."""
    # ``(caption, code, cut, cut after it, function key)``: the key is a
    # batch function's, which is drawn once, and not where a single listing
    # of the function is drawn.
    listed: list[tuple[str, str, bool, bool, str | None]] = []
    for outputs in (report.technical_evidence or {}).values():
        for o in outputs or []:
            if not tool_kinds.reads_code(o, "figures.code_listing"):
                continue
            # A failed call's answer is an error, not a listing: the ledger
            # report skips it, and no figure says a function was decompiled.
            if o.get("ok") is False:
                continue
            # An answer that lists several functions (a batch) is one listing
            # per function, captioned by the function it names.
            parts = tool_kinds.function_parts(o)
            if parts:
                listed.extend(
                    (p.where, p.code, p.cut, p.answer_cut, function_key(p.where)) for p in parts
                )
                continue
            # What is drawn is the code the answer holds: a JSON answer's code
            # field, read at the declared path or as its one code-like string,
            # with its own line breaks; a plain text answer as it was. A JSON
            # answer holding no code (a search's hits, a status record) is not
            # drawn as a decompiled function.
            facts = tool_kinds.facts_of(o)
            path = str(facts.values.get("code", "")) if facts is not None else ""
            rows = str(facts.rows or "") if facts is not None and path else ""
            body, cut = code_listing(o.get("output"), path, rows)
            if body:
                listed.append((_listed_symbol(o, facts), body, cut, False, None))
    # One function, in any spelling, is one listing: a batch's function a
    # single listing draws, or another batch listed, is not drawn again.
    seen = {function_key(item[0]) for item in listed if item[4] is None}
    drawn: list[tuple[str, str, bool, bool]] = []
    for sym, body, cut, after, key in listed:
        if key is not None:
            if key in seen:
                continue
            seen.add(key)
        drawn.append((sym, body, cut, after))
    figs: list[Figure] = []
    # A listing is printed for reading, not to compile, and a PDF viewer
    # links a URL or a host in its text: the caption and the code are
    # defanged, the run's recorded values first, then every other value.
    from maljan.reporting.defang import ProseDefanger
    from maljan.reporting.renderers.markdown import _defanged_text, run_network_values

    run_values = ProseDefanger(run_network_values(report)) if drawn else None
    for seq, (named, code, cut, after) in enumerate(drawn[:_LISTINGS]):
        sym = _defanged_text(named, run_values)
        body = _defanged_text(code, run_values)
        notes: list[str] = []
        if cut:
            notes.append(LISTING_CUT_FOR_STORAGE)
        if after:
            notes.append(ANSWER_CUT_AFTER_LISTING)
        if len(body) > _LISTING_CHARS:
            notes.append(
                f"Cut at {_LISTING_CHARS:,} of {len(body):,} characters; the evidence "
                "ledger and the JSON report carry the listing whole."
            )
        if seq == _LISTINGS - 1 and len(drawn) > _LISTINGS:
            notes.append(
                f"{len(drawn) - _LISTINGS} more decompiled functions are not drawn; the "
                "evidence ledger carries every one."
            )
        figs.append(
            Figure(
                id=f"fig-listing-{seq}",
                caption=f"Decompiled {sym}",
                kind="code_listing",
                content=f'<pre class="listing">{escape(marked_cut(body, _LISTING_CHARS))}</pre>',
                legend=" ".join(notes) or None,
            )
        )
    return figs


def _not_drawn(kind: str, exc: Exception) -> Figure:
    """The line a reader sees where a figure failed to draw, so its absence is explained."""
    said = f"Figure not drawn: {kind} ({type(exc).__name__})"
    return Figure(
        id=f"fig-not-drawn-{kind.replace('_', '-')}",
        caption=said,
        kind="not_drawn",
        content=f'<p class="figure-not-drawn">{escape(said)}</p>',
        legend=None,
    )


def build_figures(report: MalwareReport) -> list[Figure]:
    """Assemble every applicable figure in report order. A failure is said, never raised."""
    figs: list[Figure] = []
    for builder, kind in (
        (build_infection_chain, "infection_chain"),
        (build_attack_matrix, "attack_matrix"),
        (build_process_tree, "process_tree"),
        (build_entropy_chart, "entropy_chart"),
        (build_network_graph, "network_graph"),
    ):
        try:
            fig = builder(report)
        except Exception as exc:  # noqa: BLE001
            # One figure's failure never costs the report, and is never silent.
            logger.warning("A figure was not drawn (%s: %s).", kind, type(exc).__name__)
            fig = _not_drawn(kind, exc)
        if fig is not None:
            figs.append(fig)
    try:
        figs.extend(build_code_listings(report))
    except Exception as exc:  # noqa: BLE001
        logger.warning("The code listings were not drawn (%s).", type(exc).__name__)
        figs.append(_not_drawn("code_listing", exc))
    return figs
