"""Does F1 track parameter count on this task? — the C6 series analysis.

`arXiv:2606.18166` reports **parameter size as the only statistically significant
predictor** of ATT&CK-classification F1 (rho=0.85, p=0.014), with prompt
strategy, chain-of-thought and temperature all failing to predict. That result is
the strongest live threat to every claim in this project, because every claim
rests on one model: if F1 is mostly a function of size, then what we measured is
the model and not the architecture.

B8 put one comparison model against ours and found nothing (+0.0026, CI
[-0.0770, +0.0814]). A single pair can only say "these two did not separate".
This reads the same question off a **series**:

    Qwen3.6-35B-A3B (IQ3_K_R4), local     35B total /  3B active
    Nemotron-3-Super-120B-A12B           120B /  12B
    MiniMax-M3                           428B /  22B
    GLM-5.2                              744B /  40B

Same five fixtures, same `single`-arm prompt, same 2,400-token output budget —
the arms differ in the model and in nothing else that we control.

**What four points can and cannot support, decided here rather than after seeing
the numbers.** With n=4 arms there are 4! = 24 orderings, so even a *perfect*
monotone relationship has an exact two-tailed p of 0.083 and **cannot reach
p<0.05 whatever the data look like**. This script therefore reports rho with its
exact permutation p and states that floor next to it. A rho of 1.0 here would be
suggestive and not significant, and saying so before the run is the difference
between a finding and a rationalisation.

**Two confounds that no amount of arithmetic removes**, printed with the result
so they cannot be dropped in transcription:

* **quantisation** — our local arm is 3-bit; the hosted arms are served at
  precisions we neither choose nor fully know. "Parameter count" is entangled
  with "bits per parameter" across this series.
* **lab and corpus** — four models from four organisations are not four draws
  from one population. Training data, post-training and refusal behaviour all
  vary with the thing we are calling the independent variable.

The cited paper shares both weaknesses; E3 should say so rather than inherit
them silently.

Run:  .venv/bin/python tests/evaluation/eval_parameter_size_series.py
Reads only committed JSON — no services, no network.
"""

from __future__ import annotations

import json
import sys
from itertools import permutations
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

OUT_JSON = _HERE / "parameter_size_series.json"
OUT_MD = _HERE / "parameter_size_series.md"

# Below this many shared cells the arms are not being compared on the same
# evidence in any useful sense, whatever the arithmetic says. Deliberately a
# floor *and* a proportion of the largest arm (see build_report): a fixed 10
# would pass a series in which one arm scored 10 of 25 and the rest scored 25.
MIN_COMMON_CELLS = 10

# The local arm is the `single` arm of the consensus ablation: same fixtures,
# same prompt, same budget as every frontier probe. Reusing it rather than
# re-running it keeps the series anchored to a measurement the paper already
# reports, and avoids a second local number that could disagree with the first.
LOCAL_ARM = {
    "arm": "local",
    "model": "Qwen3.6-35B-A3B (IQ3_K_R4)",
    "total_params_b": 35.0,
    "active_params_b": 3.0,
    "quantisation": "IQ3_K_R4",
    "source": "consensus_ablation.json (arm=single)",
}


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested in test_parameter_size_series_scoring.py)
# ---------------------------------------------------------------------------


def ranks(values: list[float]) -> list[float]:
    """Ranks, averaging ties.

    Ties matter here: two arms can land on the same mean F1, and breaking such a
    tie by input order would let the *file reading order* decide the correlation.
    """
    order = sorted(range(len(values)), key=lambda i: values[i])
    out = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        shared = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            out[order[k]] = shared
        i = j + 1
    return out


def spearman(xs: list[float], ys: list[float]) -> float:
    """Spearman's rho. Returns 0.0 when either side is constant.

    A constant column has no ordering to correlate with, and the usual formula
    divides by zero there. Reporting 0.0 says "this tells us nothing", which is
    the truthful reading; propagating a NaN into the paper's table is not.
    """
    if len(xs) != len(ys) or len(xs) < 2:
        return 0.0
    rx, ry = ranks(xs), ranks(ys)
    n = len(rx)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry, strict=True))
    dx = sum((a - mx) ** 2 for a in rx) ** 0.5
    dy = sum((b - my) ** 2 for b in ry) ** 0.5
    if dx == 0 or dy == 0:
        return 0.0
    return num / (dx * dy)


def exact_two_tailed_p(xs: list[float], ys: list[float]) -> float:
    """Exact permutation p for rho, by enumeration.

    With four arms the asymptotic p-value is meaningless, and a t-approximation
    on three degrees of freedom would report a number no one should act on. The
    permutation distribution is only 24 points, so it is computed exactly.
    """
    n = len(xs)
    if n < 2 or n > 8:  # 8! = 40320; beyond that this is the wrong tool
        return 1.0
    observed = abs(spearman(xs, ys))
    perms = list(permutations(ys))
    hits = sum(1 for p in perms if abs(spearman(xs, list(p))) >= observed - 1e-12)
    return hits / len(perms)


def best_achievable_p(n: int) -> float:
    """The smallest two-tailed p this many arms can produce, at any effect size.

    Printed beside the result because it is the honest ceiling on what the series
    can claim. For n=4 it is 2/24 = 0.083: a perfect ordering is not significant.
    """
    if n < 2 or n > 8:
        return 1.0
    xs = [float(i) for i in range(n)]
    return exact_two_tailed_p(xs, xs)


def common_cells(arms: list[dict[str, Any]]) -> set[str]:
    """The fixture×repeat cells every arm scored.

    The arms do **not** complete the same cells: an endpoint that throttles for
    an hour leaves holes, and those holes are not random with respect to
    anything we can check. Comparing each arm's mean over *its own* completed
    cells would let "which calls got through" enter the correlation alongside
    "how large the model is", and the two are indistinguishable afterwards.

    So the series is computed on the intersection. This costs n and buys the
    only thing that makes the comparison mean what it says.
    """
    sets = [set(a.get("by_key") or {}) for a in arms]
    if not sets or any(not s for s in sets):
        return set()
    out = sets[0]
    for s in sets[1:]:
        out = out & s
    return out


def mean_over(by_key: dict[str, float], cells: set[str]) -> float | None:
    shared = [by_key[c] for c in sorted(cells) if c in by_key]
    return sum(shared) / len(shared) if shared else None


def paired_delta(a: dict[str, float], b: dict[str, float]) -> tuple[list[float], int]:
    """Per-key differences ``b - a`` over the keys both arms scored.

    Pairing is by ``sample_id:repeat``. An unpaired mean difference would mix a
    genuine model effect with whichever fixtures each arm happened to complete —
    and the arms here do *not* complete the same sets when an endpoint throttles.
    """
    shared = sorted(set(a) & set(b))
    return [b[k] - a[k] for k in shared], len(shared)


def summarise_arm(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Mean F1 and per-call scores keyed for pairing."""
    scored = [r for r in rows if "error" not in r and r.get("f1") is not None]
    keyed = {f"{r.get('sample_id')}:{r.get('repeat', 0)}": float(r["f1"]) for r in scored}
    f1s = list(keyed.values())
    return {
        "n": len(f1s),
        "mean_f1": round(sum(f1s) / len(f1s), 4) if f1s else None,
        "by_key": keyed,
        "failed": len(rows) - len(scored),
    }


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_local_arm() -> dict[str, Any] | None:
    path = _HERE / "consensus_ablation.json"
    if not path.exists():
        return None
    rows = json.loads(path.read_text())
    single = [r for r in rows if r.get("arm") == "single"]
    if not single:
        return None
    return {**LOCAL_ARM, **summarise_arm(single)}


def load_frontier_arms() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in sorted(_HERE.glob("frontier_probe*.json")):
        try:
            blob = json.loads(path.read_text())
        except Exception:  # noqa: BLE001
            continue
        rows = blob.get("per_sample") or []
        prov = blob.get("arm") or {}
        # v1 records (B8) predate per-arm provenance; the endpoint is known from
        # the model id and the queue, so it is filled in rather than dropped —
        # losing the only completed frontier arm to a schema change would be a
        # poor trade for tidiness.
        if not prov:
            prov = {
                "arm": "default",
                "model": blob.get("model", path.stem),
                "total_params_b": 120.0,
                "active_params_b": 12.0,
                "quantisation": "",
            }
        out.append({**prov, "source": path.name, **summarise_arm(rows)})
    return out


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def build_report(arms: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    usable = [a for a in arms if a.get("mean_f1") is not None and a.get("total_params_b")]
    usable.sort(key=lambda a: a["total_params_b"])

    lines = [
        "# C6 — does F1 track parameter count on this task?",
        "",
        "Same five fixtures, same `single`-arm prompt, same 2,400-token output budget.",
        "The arms differ in the model and in nothing else we control.",
        "",
        "| arm | model | total | active | mean F1 | n |",
        "|---|---|---|---|---|---|",
    ]
    for a in usable:
        lines.append(
            f"| {a.get('arm', '?')} | {a.get('model', '?')} | {a['total_params_b']:.0f}B | "
            f"{a.get('active_params_b', 0):.0f}B | {a['mean_f1']:.4f} | {a['n']} |"
        )

    result: dict[str, Any] = {
        "schema": "parameter-size-series/v1",
        "arms": [{k: v for k, v in a.items() if k != "by_key"} for a in usable],
    }

    if len(usable) < 3:
        lines += [
            "",
            f"**Incomplete: {len(usable)} of 4 arms have scores.** The correlation is not",
            "computed — a rho over the arms that happened to finish would describe which",
            "endpoints answered, not which models are larger.",
        ]
        result["status"] = "incomplete"
        return "\n".join(lines), result

    # The correlation runs on the cells every arm scored, not on each arm's own
    # completed subset — otherwise "which calls got through" is confounded with
    # "how large the model is". An arm that limped to three scored calls would
    # otherwise carry the same weight as one that completed all 25.
    cells = common_cells(usable)
    biggest = max(a["n"] for a in usable)
    result["common_cells"] = len(cells)
    result["largest_arm_n"] = biggest
    if len(cells) < max(MIN_COMMON_CELLS, int(0.6 * biggest)):
        lines += [
            "",
            f"**Not comparable: only {len(cells)} fixture-repeat cells were scored by every",
            f"arm** (largest single arm: {biggest}). The correlation is not computed. Comparing",
            "arms over cells they did not share would let endpoint availability enter the",
            "result alongside model size, and the two cannot be separated afterwards.",
            "",
            "| arm | scored | of which shared |",
            "|---|---|---|",
        ]
        for a in usable:
            lines.append(f"| {a.get('arm', '?')} | {a['n']} | {len(set(a['by_key']) & cells)} |")
        result["status"] = "not-comparable"
        return "\n".join(lines), result

    for a in usable:
        a["mean_f1_common"] = round(mean_over(a["by_key"], cells) or 0.0, 4)
    result["arms"] = [{k: v for k, v in a.items() if k != "by_key"} for a in usable]

    totals = [a["total_params_b"] for a in usable]
    actives = [a.get("active_params_b", 0.0) for a in usable]
    f1s = [a["mean_f1_common"] for a in usable]
    rho_total = spearman(totals, f1s)
    rho_active = spearman(actives, f1s)
    p_total = exact_two_tailed_p(totals, f1s)
    floor = best_achievable_p(len(usable))

    lines += [
        "",
        f"| Spearman rho, **total** parameters vs F1 | **{rho_total:+.3f}** |",
        "|---|---|",
        f"| exact two-tailed permutation p | {p_total:.3f} |",
        f"| Spearman rho, **active** parameters vs F1 | {rho_active:+.3f} |",
        f"| smallest p reachable with {len(usable)} arms | **{floor:.3f}** |",
        "",
        f"**With {len(usable)} arms, even a perfect ordering gives p = {floor:.3f}.** That",
        "ceiling is a property of the design, not of the data, and it is stated first so the",
        "rho below is read as suggestive rather than as a test.",
        "",
    ]

    prior = 0.85
    if abs(rho_total) < 0.5:
        lines += [
            "**The parameter-size prior does not reproduce here.** `arXiv:2606.18166` reports",
            f"rho={prior} on the nearest task; across a "
            f"{max(totals) / min(totals):.0f}x span of total parameters we measure",
            f"{rho_total:+.3f}. Combined with B8's paired null, the reading is that at this",
            "task, this evidence and this budget, model size is not what decides the score —",
            "which is the result that lets the rest of this project's findings be about the",
            "architecture rather than about one model.",
        ]
    else:
        lines += [
            f"**The parameter-size prior survives at rho={rho_total:+.3f}** across a",
            f"{max(totals) / min(totals):.0f}x span. `arXiv:2606.18166` reports {prior}. Every",
            "single-model claim in this work is then scoped to its model, and P8 closes as a",
            "stated limitation rather than as a cleared one.",
        ]

    lines += [
        "",
        "## Two confounds arithmetic cannot remove",
        "",
        "* **Quantisation.** The local arm is 3-bit; the hosted arms run at precisions we neither",
        "  choose nor fully know. Across this series, parameter count is entangled with bits per",
        "  parameter.",
        "* **Lab and corpus.** Four models from four organisations are not four draws from one",
        "  population — training data, post-training and refusal behaviour all vary alongside",
        "  size.",
        "",
        "`arXiv:2606.18166` shares both weaknesses. That belongs in related work rather than",
        "inherited quietly.",
    ]

    result |= {
        "status": "complete",
        "n_arms": len(usable),
        "rho_total_params": round(rho_total, 4),
        "rho_active_params": round(rho_active, 4),
        "exact_two_tailed_p": round(p_total, 4),
        "smallest_reachable_p": round(floor, 4),
        "param_span": round(max(totals) / min(totals), 1),
        "prior_rho_arxiv_2606_18166": prior,
    }
    return "\n".join(lines), result


def main() -> int:
    arms: list[dict[str, Any]] = []
    local = load_local_arm()
    if local:
        arms.append(local)
    arms.extend(load_frontier_arms())

    if not arms:
        print("no arm records found — run eval_frontier_probe.py first")
        return 1

    report, blob = build_report(arms)
    print(report)
    OUT_MD.write_text(report + "\n")
    OUT_JSON.write_text(json.dumps(blob, indent=1) + "\n")
    print(f"\nwrote {OUT_MD.name} and {OUT_JSON.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
