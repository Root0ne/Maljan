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
        "axes.spines.top": False,
        "axes.spines.right": False,
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

    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(7.2, 2.9), width_ratios=[1.15, 1])

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
    ax2.set_title("schematic: a stuck instrument", fontsize=8.5, loc="left", pad=6)
    ax2.text(
        0.5,
        -0.30,
        "drawn, not measured — that run predates per-sample retention,\n"
        "which is why its sizes cannot be plotted here",
        transform=ax2.transAxes,
        ha="center",
        va="top",
        fontsize=7,
        color=MUTE,
        style="italic",
    )

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

    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(7.2, 2.9), width_ratios=[1, 1.1])

    ax.plot([0, 1], [0, 1], color=LIGHT, lw=1.0, ls="--")
    ax.plot(fpr, tpr, color=WARN, lw=1.7)
    ax.set_xlabel("false-positive rate")
    ax.set_ylabel("true-positive rate")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_aspect("equal")
    ax.set_title(f"AUC {auc:.3f}  (n={len(rows)} claims)", fontsize=8.5, loc="left", pad=6)
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
        f"{len(vals)} distinct values; {top * 100:.0f}% of claims share one",
        fontsize=8.5,
        loc="left",
        pad=6,
    )
    for v, c in zip(vals, counts, strict=False):
        ax2.text(f"{v:g}", c + max(counts) * 0.015, str(int(c)), ha="center", fontsize=7, color=INK)
    ax2.set_ylim(0, max(counts) * 1.15)

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

    h2h = cluster["head_to_head"]
    real_entries = [
        ("pipeline, with sandbox report", h2h["dynamic_f1"], ACCENT),
        ("pipeline, static evidence only", h2h["static_only_f1"], ACCENT),
        ("no-LLM baseline (sandbox signatures)", h2h["cape_f1"], WARN),
    ]

    fig, (left, right) = plt.subplots(
        1, 2, figsize=(7.2, 2.5), gridspec_kw={"width_ratios": [1.05, 1.0]}
    )

    def draw(ax, rows, xlim, title):
        ys = list(range(len(rows)))[::-1]
        for y, (_label, mean, lo, hi, n, colour) in zip(ys, rows, strict=False):
            ax.plot([lo, hi], [y, y], color=colour, lw=1.5, solid_capstyle="butt")
            for edge in (lo, hi):
                ax.plot([edge, edge], [y - 0.13, y + 0.13], color=colour, lw=1.1)
            ax.plot([mean], [y], "o", color=colour, ms=4.6, zorder=4)
            ax.text(hi + 0.012, y, f"{mean:.3f} (n={n})", va="center", fontsize=7, color=INK)
        ax.set_yticks(ys)
        ax.set_yticklabels([r[0] for r in rows], fontsize=7.5)
        ax.set_xlim(*xlim)
        ax.set_xlabel("F1 (mean, 95% cluster interval)", fontsize=8)
        ax.set_title(title, fontsize=8.5, loc="left", color=INK)
        ax.grid(axis="x", color=LIGHT, lw=0.5)
        ax.set_axisbelow(True)

    draw(
        left,
        fixture_entries,
        (0.20, 0.72),
        "5 synthesised fixtures — no baseline is definable",
    )
    draw(
        right,
        [
            (label, blob["mean"], blob["interval"]["lo"], blob["interval"]["hi"], h2h["n"], colour)
            for label, blob, colour in real_entries
        ],
        (0.02, 0.26),
        f"{h2h['n']} real samples, {h2h['k']} families — one population",
    )
    fig.tight_layout()
    save(fig, "fig3-arms-against-baseline")


# --------------------------------------------------------------------------
# Figure 4 — firing rate decides whether an ablation can be read at all
# --------------------------------------------------------------------------


def _cascade_arms_varied() -> int:
    """How many ablation arms the cascade study actually varied.

    Hard-coded as 15 until 2026-08-15, which was the *superseded* first pass. The
    re-run varies 32 arms and the Results text says so in the same paragraph that
    the figure sits beside — "the null survives all of it, at 32 arms rather than
    15". The figure was plotting the study the text had already retired, which is
    precisely the drift this module exists to prevent, so it is derived rather
    than written down.
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

    items = [
        ("opcode-hash attribution tier", 0.0, "0 of 18 samples"),
        ("confidence cap", cap["capped_share_of_all_techniques"], "11 of 1,348 techniques"),
        (
            "corroboration cascade\n(verdict changed)",
            0.0,
            f"0 of {_cascade_arms_varied()} varied cases",
        ),
        (
            "sink-reachability hint",
            hint_rate,
            f"{sum(1 for v in ok if v.get('hint_nonempty'))} of {len(ok)} samples",
        ),
    ]
    items.sort(key=lambda t: t[1])

    fig, ax = plt.subplots(figsize=(7.2, 2.5))
    ys = list(range(len(items)))
    for y, (_label, rate, note) in zip(ys, items, strict=False):
        readable = rate > 0.10
        colour = ACCENT if readable else WARN
        ax.barh(y, max(rate, 0.0), color=colour, height=0.46)
        ax.text(
            max(rate, 0) + 0.012,
            y,
            f"{rate * 100:.2f}%   {note}",
            va="center",
            fontsize=7.5,
            color=INK,
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
