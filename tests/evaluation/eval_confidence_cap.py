"""B5 (cheap half) — how often does the only grading mechanism in the system fire?

C3 is "falsification before confidence". Its concrete form is
``extractors/capability_matrix._cap_unsupported_confidence``: a deterministic
drop to **0.40**, applied *only* to **T1027 / T1140** (obfuscation) and **T1055**
(injection) plus sub-techniques, *only* when the technique's **sole contributing
layer is `static`** — the LLM/import layer — and *only* when the matching static
evidence flag is absent.

**§3.8 changed what this experiment is for.** The confidence the pipeline
receives is ~0.98 for essentially everything, and this cap drops qualifying
claims to 0.40. So the cap is not a refinement on top of a graded score: for
those three techniques it is very nearly **the only source of grading in the
system**. The question stops being "does a graded cap beat a binary filter" and
becomes **"how often does the only grading mechanism actually fire?"**

**And it needs no LLM.** The cap is deterministic; what varies is whether its
three preconditions hold. The ablation is exact, because
``_static_evidence_flags(None)`` returns ``(True, True)`` — "no static picture
to contradict the LLM, do not cap":

  * **cap OFF** — ``build_capability_matrix(..., static=None)``
  * **cap ON**  — ``build_capability_matrix(..., static=<real StaticAnalysis>)``

Everything else is identical, so any confidence delta is the cap's.

**A second question, and it comes from a comment in the code rather than from
us.** ``_static_evidence_flags`` documents an inversion: the cap fires when
static evidence does *not* support the claim, so **a better packer detector
makes the cap fire less often**, and the net effect of improving detection
would have been *more* high-confidence hallucinated T1027. The comment says a
confidence threshold on packer matches is what breaks the inversion. This
harness measures the size of the population that inversion acts on — i.e.
whether it is a real exposure or a theoretical one.

Run:  uv run python tests/evaluation/eval_confidence_cap.py [--limit N]
No LLM, no sandbox. Pure helpers unit-tested in ``test_confidence_cap_scoring.py``.
"""

# Bootstraps sys.path before first-party imports (E402 is intentional here).
# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from tests.evaluation._tally import Tally  # noqa: E402

_OUT_FILE = _REPO_ROOT / "tests" / "evaluation" / "confidence_cap.md"
_JSON_FILE = _REPO_ROOT / "tests" / "evaluation" / "confidence_cap.json"

# Mirrors capability_matrix, deliberately re-declared so a silent change to the
# production constants shows up as a test failure rather than as a moved result.
GATED_OBFUSCATION = ("T1027", "T1140")
GATED_INJECTION = ("T1055",)
LOW_CONF_CAP = 0.40


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested without any sample)
# ---------------------------------------------------------------------------


def is_gated_technique(tid: str) -> bool:
    """True when the cap could apply to this id at all — base or sub-technique."""
    t = (tid or "").strip().upper()
    return any(t == b or t.startswith(b + ".") for b in (*GATED_OBFUSCATION, *GATED_INJECTION))


def sole_static_layer(layers: list[str]) -> bool:
    """True when ``static`` is the only contributing layer.

    This is the cap's second precondition and the one that makes it rare: any
    corroboration from yara, sigma, dynamic or network exempts the claim, which
    is deliberate — the cap exists to discipline *LLM-only* guesses.
    """
    normalised = {str(x).strip().lower() for x in layers if str(x).strip()}
    return normalised == {"static"}


def cap_delta(before: float, after: float) -> float:
    """How far the cap moved a claim. Zero when it did not apply."""
    return round(before - after, 6)


def firing_rate(fired: int, eligible: int) -> float:
    """Share of eligible claims the cap actually moved. 0.0 when none were eligible."""
    if eligible <= 0:
        return 0.0
    return fired / eligible


@dataclass
class SampleResult:
    sample: str
    total_techniques: int
    gated_techniques: int
    gated_sole_static: int
    capped: int
    mean_delta: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def summarise(results: list[SampleResult]) -> dict[str, Any]:
    """Corpus-level totals. Rates are computed from totals, not averaged per sample —
    averaging per-sample rates would weight a one-technique sample like a
    twenty-technique one."""
    total = sum(r.total_techniques for r in results)
    gated = sum(r.gated_techniques for r in results)
    sole = sum(r.gated_sole_static for r in results)
    capped = sum(r.capped for r in results)
    return {
        "samples": len(results),
        "techniques_total": total,
        "gated_techniques": gated,
        "gated_share_of_all": round(gated / total, 4) if total else 0.0,
        "gated_and_sole_static": sole,
        "capped": capped,
        "cap_fire_rate_among_gated": round(firing_rate(capped, gated), 4),
        "cap_fire_rate_among_eligible": round(firing_rate(capped, sole), 4),
        "capped_share_of_all_techniques": round(capped / total, 4) if total else 0.0,
        "samples_with_any_cap": sum(1 for r in results if r.capped > 0),
    }


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------


def measure_sample(
    sample_path: Path, yara_layer: Any, tool_catalog: str, tally: Tally
) -> SampleResult | None:
    """Build the capability matrix with the cap OFF and ON; diff the confidences."""
    from maljan.analysis.ttp_cascade import TTPCascadeEngine
    from maljan.extractors.capability_matrix import build_capability_matrix
    from maljan.extractors.pe_extractor import build_static_analysis
    from tests.evaluation.eval_layer0_contribution import collect_isrs

    isrs = collect_isrs(sample_path, yara_layer, tool_catalog)
    if not isrs:
        tally.drop("no_static")
        return None
    try:
        static = build_static_analysis(sample_path=str(sample_path))
    except Exception as exc:  # noqa: BLE001 — unparseable members are skipped, not fatal
        tally.drop("unparseable", detail=type(exc).__name__)
        return None
    if static is None:
        tally.drop("no_static")
        return None

    summary = TTPCascadeEngine().compute(isrs)

    # static=None is the cap-OFF arm by construction: _static_evidence_flags(None)
    # returns (True, True), i.e. "no static picture to contradict the LLM".
    _cells_off, maps_off = build_capability_matrix(
        cascade_summary=summary, isr_reports=isrs, static=None
    )
    _cells_on, maps_on = build_capability_matrix(
        cascade_summary=summary, isr_reports=isrs, static=static
    )

    off = {m.technique_id: m for m in maps_off if getattr(m, "technique_id", None)}
    on = {m.technique_id: m for m in maps_on if getattr(m, "technique_id", None)}

    gated = 0
    sole = 0
    capped = 0
    deltas: list[float] = []
    for tid, m_off in off.items():
        if not is_gated_technique(tid):
            continue
        gated += 1
        layers = list(getattr(m_off, "contributing_layers", None) or [])
        if sole_static_layer(layers):
            sole += 1
        m_on = on.get(tid)
        if m_on is None:
            continue
        d = cap_delta(
            float(getattr(m_off, "confidence", 0.0)),
            float(getattr(m_on, "confidence", 0.0)),
        )
        if d > 0:
            capped += 1
            deltas.append(d)

    tally.parse_ok()
    tally.score_ok()
    return SampleResult(
        sample=sample_path.name,
        total_techniques=len(off),
        gated_techniques=gated,
        gated_sole_static=sole,
        capped=capped,
        mean_delta=round(sum(deltas) / len(deltas), 4) if deltas else 0.0,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="B5 cheap half — confidence-cap firing rate.")
    ap.add_argument("--limit", type=int, default=0, help="Stop after N parsed samples.")
    ap.add_argument("--samples-dir", type=str, default="data/samples")
    ap.add_argument("--tool-catalog", type=str, default="data/tool_artifacts_v1.json")
    args = ap.parse_args()

    from maljan.analysis.yara_layer import YaraLayer

    try:
        yara_layer: Any = YaraLayer.from_default_rules()
    except Exception as exc:  # noqa: BLE001
        print(f"YaraLayer unavailable ({exc}); continuing without it.", flush=True)
        yara_layer = None

    samples_dir = Path(args.samples_dir)
    if not samples_dir.is_dir():
        print(f"No sample directory at {samples_dir} — aborting.", flush=True)
        return 1
    # Same extension filter as eval_layer0_contribution, so the corpus matches §1.10's.
    paths = sorted(
        p
        for p in samples_dir.iterdir()
        if p.is_file() and p.suffix.lower() in {".exe", ".dll", ".sys", ".scr"}
    )
    if not paths:
        print(f"No PE samples in {samples_dir} — aborting.", flush=True)
        return 1
    print(f"samples: {len(paths)}", flush=True)

    results: list[SampleResult] = []
    tally = Tally()
    for i, path in enumerate(paths, 1):
        if i % 25 == 0:
            print(f"  {i}/{len(paths)}", flush=True)
        tally.attempt()
        try:
            res = measure_sample(path, yara_layer, args.tool_catalog, tally)
        except Exception as exc:  # noqa: BLE001 — one bad sample must not end the run
            tally.drop("unparseable", detail=type(exc).__name__)
            print(f"  skip {path.name}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        if res is not None:
            results.append(res)
            if args.limit and len(results) >= args.limit:
                break

    stats = summarise(results)
    stats["population"] = tally.as_dict()
    hist = Counter(r.capped for r in results)

    gated_names = ", ".join((*GATED_OBFUSCATION, *GATED_INJECTION))
    lines = [
        "# B5 (cheap half) — how often the confidence cap fires",
        "",
        "The cap (`_cap_unsupported_confidence`) drops a claim to **0.40**, but only for",
        f"**{gated_names}** and their sub-techniques, only when the sole contributing layer",
        "is `static`, and only when the matching static evidence is",
        "absent. §3.8 showed the incoming confidence is ~0.98 for essentially everything, so for",
        "these techniques the cap is very nearly the **only** source of grading in the system.",
        "",
        "Ablation is exact and server-free: `static=None` disables the cap by construction",
        "(`_static_evidence_flags(None)` returns `(True, True)`), everything else identical.",
        "",
        "| quantity | value |",
        "|---|---|",
        f"| samples with evidence | {stats['samples']} |",
        f"| techniques total | {stats['techniques_total']} |",
        f"| gated techniques (T1027/T1140/T1055 + subs) | {stats['gated_techniques']} "
        f"({stats['gated_share_of_all']:.1%} of all) |",
        f"| …of which sole-layer `static` (cap eligible) | {stats['gated_and_sole_static']} |",
        f"| **capped** | **{stats['capped']}** |",
        f"| cap fire rate among gated | {stats['cap_fire_rate_among_gated']:.1%} |",
        f"| cap fire rate among eligible | {stats['cap_fire_rate_among_eligible']:.1%} |",
        f"| **capped share of ALL techniques** | "
        f"**{stats['capped_share_of_all_techniques']:.2%}** |",
        f"| samples where the cap fired at least once | {stats['samples_with_any_cap']} |",
        "",
        f"Caps per sample: {dict(sorted(hist.items()))}",
        "",
    ]
    report = "\n".join(lines)
    print(report, flush=True)
    try:
        _OUT_FILE.write_text(report + "\n", encoding="utf-8")
        _JSON_FILE.write_text(
            json.dumps({"summary": stats, "per_sample": [r.to_dict() for r in results]}, indent=2)
            + "\n",
            encoding="utf-8",
        )
        print(f"Wrote {_OUT_FILE} and {_JSON_FILE}", flush=True)
    except OSError as exc:
        print(f"Could not write report: {exc}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
