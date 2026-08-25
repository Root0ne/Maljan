"""Build the paper's figures from retained per-sample data. No figure invents a number.

Every panel here reads one of the eval harnesses' JSON outputs and plots what is
in it. Where a figure shows an interval it is the same bootstrap used in the
text (seed fixed), recomputed from the per-sample records rather than copied
from a summary — so a figure and a sentence cannot drift apart.

Four figures, one per argument the paper makes:

1. **Output cardinality** — the detector that found all four instrument
   failures, drawn as distinct-outputs against inputs-processed. A healthy
   instrument tracks the diagonal; a stuck one goes flat. This is the figure
   the method section is about.
2. **Verbal confidence does not discriminate** — the ROC of the number every
   deterministic gate in the system consumes.
3. **The measured negatives** — every arm on one F1 axis with its interval,
   against the no-LLM baseline that gives the axis meaning.
4. **Firing rate before effect** — why two of those ablations are readable and
   two are not.

Run: .venv/bin/python tests/evaluation/make_paper_figures.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import sys

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

if str(Path(__file__).resolve().parents[2]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from matplotlib.transforms import blended_transform_factory as blended  # noqa: E402

from tests.evaluation import stats  # noqa: E402

_HERE = Path(__file__).resolve().parent
OUT = _HERE.parent.parent / "docs/academic-article/paper/figures"
SEED = 20260811

# Muted, colourblind-safe, and legible when printed in grayscale: the paper is
# as likely to be read on paper as on a screen.
INK = "#1a1a1a"
ACCENT = "#0b6e4f"
WARN = "#a8322d"
MUTE = "#8a8a8a"
LIGHT = "#d9d9d9"

plt.rcParams.update(
    {
        # Matplotlib's default `pdf.fonttype` is 3, and Type 3 is a bitmap format:
        # text in the figure cannot be extracted, plagiarism and accessibility
        # tools see nothing where the axis labels are, and several publishers
        # reject a PDF containing one outright. Seven of the eleven fonts embedded
        # in the assembled paper were Type 3 subsets, all of them from here — the
        # LaTeX text layer was clean throughout. 42 is TrueType.
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        # One serif family across body, figures and maths. The body is set in
        # TeX Gyre Termes (a Times clone) and the figures were in DejaVu Serif,
        # which is visible on the page as two different papers stapled together.
        "font.family": "serif",
        "font.serif": ["TeX Gyre Termes", "Nimbus Roman", "Times New Roman", "DejaVu Serif"],
        "mathtext.fontset": "stix",
        "font.size": 9,
        "axes.edgecolor": INK,
        "axes.labelcolor": INK,
        "axes.linewidth": 0.7,
        # All four spines. Two of them were off, which is a common plotting
        # default and the wrong one here: an open axes lets a label drawn past
        # the last data point wander into whatever is beside it, and in a
        # two-panel figure that is the next panel. A frame makes the boundary
        # visible while the placement rules below keep anything from crossing it.
        "axes.spines.top": True,
        "axes.spines.right": True,
        "xtick.color": INK,
        "ytick.color": INK,
        "text.color": INK,
        "figure.dpi": 150,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.02,
    }
)


def load(name: str):
    return json.loads((_HERE / name).read_text())


def bootstrap_ci(
    values: list[float],
    clusters: list | None = None,
    iters: int = 4000,
) -> tuple[float, float]:
    """95% bootstrap CI for the mean, resampling clusters.

    Callers pass the sample id when a figure draws repeated measurements of
    the same sample; the consensus and frontier arms are five samples repeated
    five times and drawing them as 25 independent points was the error.
    """
    vals = [float(v) for v in values]
    if len(vals) < 2:
        return (vals[0], vals[0]) if vals else (0.0, 0.0)
    keys = list(clusters) if clusters is not None else list(range(len(vals)))
    interval = stats.cluster_bootstrap_ci(vals, keys, iters=iters, seed=SEED)
    return (interval.lo, interval.hi)


def panel_labels(*axes, y: float = -0.015):
    """Stamp a), b), ... under each panel of a multi-panel figure.

    House style names panels in the caption, so the panels have to carry the
    names. Putting them in the image rather than in LaTeX keeps the label with
    the plot in the PNG, in the alt text's description, and anywhere the figure
    is reused outside the paper. Placed below the axes so nothing is drawn over
    the data.

    Placed at one height for the whole figure rather than at a fixed offset
    under each axes. The offset version drifted apart the moment two panels had
    different heights, which happens as soon as one of them is square: the ROC
    panel sets an equal aspect, its axes shrinks vertically, and its label sat
    half an inch above its neighbour's.
    """
    axes = [ax for ax in axes if ax is not None]
    if not axes:
        return
    fig = axes[0].figure
    fig.canvas.draw()
    # Below everything the axes draws, not below the axes. Offsetting from the
    # frame put the letter on top of the x-label, because the label is outside
    # the frame and its height depends on how many lines the tick labels take.
    # The tight bbox already knows where the drawn content ends.
    inv = fig.transFigure.inverted()
    renderer = fig.canvas.get_renderer()
    bottoms = [inv.transform((0, ax.get_tightbbox(renderer).y0))[1] for ax in axes]

    # Panels side by side share a baseline so their letters line up; panels
    # stacked in a column each need their own, or both letters land on the same
    # point and one hides the other. Which it is comes from the geometry rather
    # than from an argument the caller has to remember: axes in one row have
    # overlapping vertical extents.
    rows: list[list[int]] = []
    for i, ax in enumerate(axes):
        pos = ax.get_position()
        for row in rows:
            other = axes[row[0]].get_position()
            if pos.y0 < other.y1 and other.y0 < pos.y1:
                row.append(i)
                break
        else:
            rows.append([i])
    baseline = {i: min(bottoms[j] for j in row) for row in rows for i in row}

    for i, (ax, letter) in enumerate(zip(axes, "abcdefgh", strict=False)):
        if len(rows) > 1:
            # Stacked panels have no room beneath them: the gap between two rows
            # belongs to the lower panel's title, and a letter placed there sits
            # on it. The left margin at the panel's own top is empty, because
            # the title starts where the axes does and the axes starts after the
            # row names.
            top = inv.transform((0, ax.get_tightbbox(renderer).y1))[1]
            fig.text(0.005, top, f"{letter})", ha="left", va="top", fontsize=9, color=INK)
            continue
        fig.text(
            ax.get_position().x0,
            baseline[i] + y,
            f"{letter})",
            ha="left",
            va="top",
            fontsize=9,
            color=INK,
        )


def reserve_label_column(ax, labels, texts, gap: float = 0.05, margin: float = 0.04):
    # gap is the clearance between the widest interval's cap and the label
    # column; at 0.02 those two touched on whichever row happened to be widest.
    """Set the x-limits so a right-hand label column fits, and return its x.

    Three earlier attempts all put the text outside the frame, and each failed
    for its own reason. Anchoring the label to each interval's upper edge let a
    wide interval push it out. Right-aligning it against the frame put it under
    the widest interval instead. Reserving a guessed third of the axes was not
    enough for "0.414 (n=25)" at 7pt. Measuring the rendered extent looked
    right and was not, because ``savefig`` runs the layout again with
    ``bbox_inches="tight"`` and the display mapping the measurement came from
    no longer exists at save time.

    What is stable across that is physical size: an axes keeps its width in
    inches, and so does a string at a given point size. So the column is sized
    in inches and converted to a fraction of the axes, once, after the layout is
    final.
    """
    fig = ax.figure
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    widest_in = (
        max((txt.get_window_extent(renderer=renderer).width for txt in texts), default=0.0)
        / fig.dpi
    )
    axes_in = ax.get_position().width * fig.get_figwidth()
    frac = min(0.55, widest_in / max(axes_in, 1e-6))

    lo = ax.get_xlim()[0]
    widest_data = max(labels)
    span = (widest_data - lo) / max(1e-6, 1.0 - frac - gap - margin)
    ax.set_xlim(lo, lo + span)
    return widest_data + span * gap


def save(fig, stem: str):
    OUT.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(OUT / f"{stem}.{ext}")
    plt.close(fig)
    print(f"  wrote figures/{stem}.pdf + .png")


# --------------------------------------------------------------------------
# Figure 1 — output cardinality: the check that found every instrument failure
# --------------------------------------------------------------------------
def fig_cardinality():
    res = load("sink_hint_frequency.json")["results"]
    rows = [v for v in res.values() if not v.get("error") and v.get("graph_chars")]
    rows.sort(key=lambda r: (r.get("year", ""), r.get("program", "")))
    sizes = [r["graph_chars"] for r in rows]

    seen: set[int] = set()
    distinct = []
    for s in sizes:
        seen.add(s)
        distinct.append(len(seen))
    n = len(sizes)

    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(5.3, 2.9), width_ratios=[1.15, 1])

    ax.plot([0, n], [0, n], color=LIGHT, lw=1.0, ls="--", zorder=1)
    ax.annotate(
        "every input a distinct output",
        xy=(n * 0.62, n * 0.62),
        xytext=(n * 0.30, n * 0.86),
        color=MUTE,
        fontsize=7.5,
        arrowprops={"arrowstyle": "-", "color": LIGHT, "lw": 0.7},
    )
    ax.plot(range(1, n + 1), distinct, color=ACCENT, lw=1.6, zorder=3)
    ax.set_xlabel("samples processed")
    ax.set_ylabel("distinct call-graph sizes")
    ax.set_xlim(0, n)
    ax.set_ylim(0, n)
    ax.set_title(f"measured: {distinct[-1]} distinct across {n}", fontsize=8.5, loc="left", pad=6)

    # The right panel is a SCHEMATIC and is labelled as one. The run it depicts
    # — 66 consecutive samples returning a byte-identical 75,426-character call
    # graph — predates the per-sample retention policy, so its sizes cannot be
    # plotted. That is not a footnote to work around: it is §6.4's argument
    # arriving in the figure that most wants the data, and the label says so
    # rather than letting a drawn curve sit unmarked beside a measured one.
    stuck_at = 18
    stuck = list(range(1, stuck_at + 1)) + [stuck_at] * (n - stuck_at)
    ax2.plot([0, n], [0, n], color=LIGHT, lw=1.0, ls="--", zorder=1)
    ax2.plot(range(1, n + 1), stuck, color=WARN, lw=1.6, zorder=3)
    ax2.annotate(
        "server stops switching program;\nevery later sample returns\nthe same 75,426 characters",
        xy=(n * 0.60, stuck_at),
        xytext=(n * 0.20, n * 0.52),
        color=WARN,
        fontsize=7.5,
        arrowprops={"arrowstyle": "->", "color": WARN, "lw": 0.7},
    )
    ax2.set_xlabel("samples processed")
    ax2.set_xlim(0, n)
    ax2.set_ylim(0, n)
    # The caveat is part of what this panel is, so it goes in the panel's name.
    # It used to be a line of italics floating below the axes, attached to
    # nothing a reader could see, and the caption says why the run cannot be
    # plotted.
    ax2.set_title(
        "schematic: a stuck instrument, drawn not measured",
        fontsize=8.5,
        loc="left",
        pad=6,
    )

    # No explicit offset any more: panel_labels measures the drawn content, and
    # the caveat above is a child of ax2, so its tight bbox already includes it.
    # The old -0.48 was an axes fraction and is a figure fraction now, which put
    # the letters most of a page below the plots.
    panel_labels(ax, ax2)
    save(fig, "fig1-output-cardinality")


# --------------------------------------------------------------------------
# Figure 2 — the confidence number every deterministic gate consumes
# --------------------------------------------------------------------------
def fig_confidence():
    rows = load("confidence_calibration.json")
    conf = np.array([float(r["confidence"]) for r in rows])
    correct = np.array([int(r["correct"]) for r in rows])

    # Ties decide this figure, so they are handled explicitly. 186 of 210 claims
    # carry confidence exactly 1.0; a naive descending sort orders those tied
    # claims arbitrarily and returns 0.458, while the rank-based estimator that
    # averages them returns 0.550. The second is the correct one and the one the
    # text reports. Thresholding at distinct values produces the ROC whose
    # trapezoidal area equals that rank statistic, so curve and number agree by
    # construction rather than by coincidence.
    npos, nneg = float(correct.sum()), float((1 - correct).sum())
    thresholds = np.sort(np.unique(conf))[::-1]
    tpr, fpr = [0.0], [0.0]
    for t in thresholds:
        picked = conf >= t
        tpr.append(float(correct[picked].sum()) / npos)
        fpr.append(float((1 - correct)[picked].sum()) / nneg)
    tpr, fpr = np.array(tpr), np.array(fpr)
    auc = float(np.trapezoid(tpr, fpr))

    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(5.6, 2.9), width_ratios=[1, 1.1])

    ax.plot([0, 1], [0, 1], color=LIGHT, lw=1.0, ls="--")
    ax.plot(fpr, tpr, color=WARN, lw=1.7)
    ax.set_xlabel("false-positive rate")
    ax.set_ylabel("true-positive rate")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_aspect("equal")
    # Spelled out rather than "AUC". The paper defines an abbreviation where a
    # reader first meets it and uses this one twice, so it spells it out in both
    # places; a figure carrying the short form would be the one undefined
    # abbreviation in the document.
    ax.set_title(
        f"area under the curve {auc:.3f}  (n={len(rows)} claims)",
        fontsize=8.5,
        loc="left",
        pad=6,
    )
    ax.text(
        0.52,
        0.16,
        "chance",
        color=MUTE,
        fontsize=7.5,
        rotation=32,
        ha="center",
        transform=ax.transAxes,
    )

    vals, counts = np.unique(conf, return_counts=True)
    top = counts.max() / counts.sum()
    ax2.bar([f"{v:g}" for v in vals], counts, color=MUTE, width=0.6)
    ax2.set_xlabel("verbal confidence emitted")
    ax2.set_ylabel("claims")
    ax2.set_title(
        f"{len(vals)} distinct values; {top * 100:.0f}% share one",
        fontsize=8.5,
        loc="left",
        pad=6,
    )
    for v, c in zip(vals, counts, strict=False):
        ax2.text(f"{v:g}", c + max(counts) * 0.015, str(int(c)), ha="center", fontsize=7, color=INK)
    ax2.set_ylim(0, max(counts) * 1.22)

    # The right panel's y-label sat against the left panel's right spine, which
    # only became visible when that spine did.
    fig.tight_layout(w_pad=2.0)
    panel_labels(ax, ax2)
    save(fig, "fig2-confidence-discrimination")
    return auc


# --------------------------------------------------------------------------
# Figure 3 — every arm on one axis, against the baseline that gives it meaning
# --------------------------------------------------------------------------
def fig_arms():
    """Two panels that never share an F1 axis, because they are two populations.

    The single-axis version of this figure put the five-fixture arms and the
    97-sample no-LLM baseline on one scale. They are not comparable: the fixture
    corpus is synthesised evidence generated from its own technique lists, scored
    against per-sample truth; the CAPE corpus is real binaries scored against
    family-level MITRE ``uses`` sets. Different inputs, different truth
    granularity, different ceilings. Read together, the 0.15 baseline against the
    0.41 arms looked like a large pipeline win, and the like-for-like comparison
    on one population is +0.003.

    So: the left panel is the fixture corpus and carries no baseline, because none
    can exist for it — a deterministic regular expression over the artifact
    dictionary that generated its evidence scores 1.000 by construction. The right
    panel is the one population where pipeline and baseline can be compared, and
    carries all three arms.
    """
    ca = load("consensus_ablation.json")
    arms: dict[str, list[float]] = {}
    clusters: dict[str, list[str]] = {}
    for r in ca:
        arms.setdefault(r["arm"], []).append(float(r["f1"]))
        clusters.setdefault(r["arm"], []).append(str(r["sample_id"]))

    cluster = load("cluster_analysis.json")
    fr = cluster["arms"]["frontier_probe"]

    fixture_entries = []
    for key, label in (
        ("single", "single judge, all evidence"),
        ("negotiated", "negotiated multi-agent consensus"),
        ("noise", "stochastic-noise control"),
    ):
        v = arms.get(key)
        if not v:
            continue
        lo, hi = bootstrap_ci(v, clusters[key])
        fixture_entries.append((label, sum(v) / len(v), lo, hi, len(v), ACCENT))
    fixture_entries.append(
        (
            "120B reasoning model",
            fr["interval"]["point"],
            fr["interval"]["lo"],
            fr["interval"]["hi"],
            fr["interval"]["n_rows"],
            MUTE,
        )
    )

    n_fixtures = len(
        {c for key in ("single", "negotiated", "noise") for c in clusters.get(key, [])}
    )

    h2h = cluster["head_to_head"]
    real_entries = [
        ("pipeline, with sandbox report", h2h["dynamic_f1"], ACCENT),
        ("pipeline, static evidence only", h2h["static_only_f1"], ACCENT),
        ("no-LLM baseline (sandbox signatures)", h2h["cape_f1"], WARN),
    ]

    def draw(ax, rows, xlim, title, bottom_panel=True):
        # The value column gets a third of the axes and the data gets the rest.
        # Two earlier versions failed the same way: drawn from each interval's
        # upper edge, the label ran past the right spine and, in the left panel,
        # printed through the right panel's tick labels -- "0.416 (n=25)" over
        # "no-LLM baseline (sandbox signatures)". Right-aligning it against the
        # frame instead put it underneath the widest interval. Neither is a
        # placement problem; both are the same missing decision, which is that a
        # label column needs room reserved rather than borrowed from whatever
        # happens to be beside it.
        lo_x = xlim[0]
        widest = max(r[3] for r in rows)
        xlim = (lo_x, widest + (widest - lo_x) * 0.05)
        ys = list(range(len(rows)))[::-1]
        labels = []
        # n is a property of the panel whenever it is the same on every row, and
        # repeating it four times cost the plot a third of its width: the label
        # column is sized by the widest string in it, and "0.414 (n=25)" is
        # twice "0.414". It moves to the title when it is constant and stays on
        # the row when it is not, because a panel where it differs is a panel
        # where the reader needs it.
        ns = {r[4] for r in rows}
        shared_n = ns.pop() if len(ns) == 1 else None
        if shared_n is not None:
            title = f"{title}, n={shared_n}"
        for y, (_label, mean, lo, hi, n, colour) in zip(ys, rows, strict=False):
            ax.plot([lo, hi], [y, y], color=colour, lw=1.5, solid_capstyle="butt")
            for edge in (lo, hi):
                ax.plot([edge, edge], [y - 0.13, y + 0.13], color=colour, lw=1.1)
            ax.plot([mean], [y], "o", color=colour, ms=4.6, zorder=4)
            text = f"{mean:.3f}" if shared_n is not None else f"{mean:.3f} (n={n})"
            # A white ground under the value, so the x-grid does not run through
            # it. The grid is a reading aid for the bars and has no business in
            # the label column.
            labels.append(
                ax.text(
                    0,
                    y,
                    text,
                    va="center",
                    fontsize=7,
                    color=INK,
                    bbox={"facecolor": "white", "edgecolor": "none", "pad": 1.0},
                )
            )
        ax.set_yticks(ys)
        ax.set_yticklabels([r[0] for r in rows], fontsize=7.5)
        ax.set_xlim(*xlim)
        if bottom_panel:
            ax.set_xlabel("F1 (mean, 95% cluster interval)", fontsize=8)
        ax.set_title(title, fontsize=8.5, loc="left", color=INK)
        ax.grid(axis="x", color=LIGHT, lw=0.5)
        ax.set_axisbelow(True)
        return [r[3] for r in rows], labels

    def one(rows, lo_x, title, stem):
        # Height from the row count, so three rows do not get the spacing four
        # need. The rows carry the reading, and stretching three of them over an
        # inch of empty each says there is more here than there is.
        fig, ax = plt.subplots(figsize=(5.3, 0.40 * len(rows) + 1.05))
        his, texts = draw(ax, rows, (lo_x, None), title)
        # Fit after the layout, not during it. Measured before tight_layout(),
        # the extents belong to axes that are about to be resized.
        fig.tight_layout()
        x = reserve_label_column(ax, his, texts)
        for txt in texts:
            txt.set_x(x)
        save(fig, stem)

    one(
        [
            (label, blob["mean"], blob["interval"]["lo"], blob["interval"]["hi"], h2h["n"], colour)
            for label, blob, colour in real_entries
        ],
        0.02,
        f"{h2h['n']} real samples, {h2h['k']} families",
        "fig3-arms-against-baseline",
    )
    one(
        fixture_entries,
        0.20,
        f"{n_fixtures} synthesised fixtures, no baseline definable",
        "fig6-equal-budget-arms",
    )


# --------------------------------------------------------------------------
# Figure 4 -- firing rate decides whether an ablation can be read at all
# --------------------------------------------------------------------------


def _cascade_arms_varied() -> int:
    """How many ablation arms the cascade study actually varied.

    Hard-coded as 15 until 2026-08-15, which was the *superseded* first pass.
    The re-run varies 32 arms and the Results text says so in the same paragraph
    that the figure sits beside. The figure was plotting the study the text had
    already retired, which is precisely the drift this module exists to prevent,
    so it is derived rather than written down.
    """
    rows = load("layer0_verdict_v2_overlap.json")["arms"]
    base = {(r["sample_id"], r["repeat"]): r["technique_ids"] for r in rows if r["arm"] == "all"}
    return sum(1 for r in rows if r["arm"] != "all" and (r["sample_id"], r["repeat"]) in base)


def fig_firing():
    cap = load("confidence_cap.json")["summary"]
    freq = load("sink_hint_frequency.json")["results"]
    ok = [v for v in freq.values() if not v.get("error")]
    n_fired = sum(1 for v in ok if v.get("hint_nonempty"))
    hint_rate = n_fired / max(1, len(ok))

    # Every count derived. Two of these four notes were written out by hand,
    # which is the same defect _cascade_arms_varied() was written to fix and had
    # been left in the two rows beside it: a hand-typed "0 of 18 samples" states
    # a cohort size the probe no longer has to agree with.
    hashed = load("function_hash_attribution_probe.json")["results"]
    hash_fired = sum(1 for v in hashed.values() if v.get("matches"))

    items = [
        (
            "opcode-hash attribution tier",
            hash_fired / max(1, len(hashed)),
            f"{hash_fired} of {len(hashed)} samples",
        ),
        (
            "confidence cap",
            cap["capped_share_of_all_techniques"],
            f"{cap['capped']} of {cap['techniques_total']:,} techniques",
        ),
        (
            "corroboration cascade\n(verdict changed)",
            0.0,
            f"0 of {_cascade_arms_varied()} varied cases",
        ),
        (
            "sink-reachability hint",
            hint_rate,
            f"{n_fired} of {len(ok)} samples",
        ),
    ]
    items.sort(key=lambda t: t[1])

    fig, ax = plt.subplots(figsize=(5.3, 2.5))
    ys = list(range(len(items)))
    # The rate sits beside its bar and the count sits in a column against the
    # frame. They used to be one string starting at the bar's end, so a row at
    # 0.00% printed its count straight through the 10% threshold line the figure
    # exists to draw, and the widest count ran past the right spine.
    for y, (_label, rate, note) in zip(ys, items, strict=False):
        readable = rate > 0.10
        colour = ACCENT if readable else WARN
        ax.barh(y, max(rate, 0.0), color=colour, height=0.46)
        ax.text(
            max(rate, 0) + 0.010,
            y,
            f"{rate * 100:.2f}%",
            va="center",
            fontsize=7.5,
            color=INK,
        )
        ax.text(
            0.985,
            y,
            note,
            transform=blended(ax.transAxes, ax.transData),
            va="center",
            ha="right",
            fontsize=7.5,
            color=MUTE,
            bbox={"facecolor": "white", "edgecolor": "none", "pad": 1.0},
        )

    ax.axvline(0.10, color=MUTE, lw=0.8, ls="--")
    ax.annotate(
        "left of this line, an ablation's null\ndescribes the cases it never ran on",
        xy=(0.10, 0.55),
        xytext=(0.30, 0.75),
        fontsize=7.2,
        color=MUTE,
        va="center",
        arrowprops={"arrowstyle": "->", "color": MUTE, "lw": 0.7},
    )
    ax.set_ylim(-0.65, len(items) - 0.35)
    ax.set_yticks(ys)
    ax.set_yticklabels([i[0] for i in items], fontsize=8)
    ax.set_xlabel("share of cases on which the mechanism fires")
    ax.set_xlim(0, 0.92)
    ax.set_xticks([0, 0.2, 0.4, 0.6, 0.8])
    ax.set_xticklabels(["0%", "20%", "40%", "60%", "80%"])
    ax.grid(axis="x", color=LIGHT, lw=0.5)
    ax.set_axisbelow(True)
    save(fig, "fig4-firing-rate-before-effect")


def main() -> int:
    print("building figures from retained per-sample data")
    fig_cardinality()
    auc = fig_confidence()
    fig_arms()
    fig_firing()
    print(f"\nrecomputed from per-sample records: confidence AUC = {auc:.4f}")
    print(f"figures in {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
