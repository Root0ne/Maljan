"""MaLAware-style narrative-quality evaluation: LLM narrative vs deterministic fallback.

The report's natural-language narrative (executive summary, capabilities prose,
defensive recommendations) is produced by ``NarrativeAgent``
(``src/maljan/reporting/narrative_agent.py``). MaLAware [Saha et al., MSR 2025]
is cited for its *evaluation protocol* — score LLM-generated malware narratives
and check that small local models suffice for the narration task. This harness
delivers that protocol.

Design (mindful of findings-log section 3.4: an N=1 LLM measurement is not a
valid instrument):
  * **Paired** — every fixed evidence bundle is narrated by both arms: the LLM
    (``narrative_agent.generate``) and the deterministic fallback template
    (``MalwareReportBuilder.apply_fallback_narrative``). Per-sample difficulty
    cancels in the paired delta.
  * **Forced/structured output** — the LLM arm already emits ``NarrativeOutput``
    via ``with_structured_output``, removing truncation as a variable.
  * **N >> 1** — every sample is generated ``--repeats K`` times so decoding
    variance is captured; we report mean +/- bootstrap CI and a sign test, not a
    single number.
  * **Equal budget** — the LLM arm runs under the narrative LLM's pinned
    ``max_tokens`` cap; the fallback arm is a zero-budget reference baseline.

The repo vendors no human-written reference *prose* — only technique-id
ground-truth lists. So "quality" is operationalised as **faithfulness**
(narrative does not cite techniques absent from the evidence), **coverage**
(it surfaces the evidence's techniques), **structure** (schema/length/format
compliance), and **linter-cleanliness** (no fp_linter C2/C3). All scoring is
automated and deterministic — no human prose, no new dependency.

Run:  uv run python tests/evaluation/eval_narrative_quality.py [--limit N] [--repeats K] [--smoke]
Requires a live llama-server (the narrative LLM) for the LLM arm. Measurement
tool, not a pytest test (the pure scoring functions are unit-tested in
``test_narrative_quality_scoring.py``).
"""

# Bootstraps sys.path before first-party imports (E402 is intentional here).
# ruff: noqa: E402

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from maljan.core.config import get_settings
from maljan.core.container import ServiceContainer
from maljan.qa.fp_linter import lint_report
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import (
    CapabilityCell,
    FamilyAttribution,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    SeverityAssessment,
    TTPMapping,
)
from tests.evaluation import stats

# No seed constant existed here: the estimator hard-coded one in its body and
# wrote none into the artifact, so a published interval could not be reproduced
# from its own file. Dated to the run that produced the checkpoint.
SEED = 20260811

_FIXTURE_DIR = _REPO_ROOT / "tests" / "evaluation" / "fixtures"
_GT_MALWARE_DIR = _REPO_ROOT / "tests" / "evaluation" / "ground_truth" / "attck_malware"
# Outputs land in this directory, beside the harness that produced them.
#
# These paths were `D:/tmp/...` — valid on the Windows box this was first
# written on, and on Linux a *relative* directory literally named `D:` in
# whatever the working directory happened to be. Nothing errors; the file is
# written and then is wherever the run was launched from, under a name no one
# thinks to look for. That is a silent retention failure in the harnesses whose
# retained output §4.5 depends on, and one of these four is the withdrawn
# n=210 drift study.
_OUTPUT_DIR = Path(__file__).resolve().parent
_OUT_FILE = _OUTPUT_DIR / "narrative_quality.md"
_DEFAULT_CHECKPOINT = _OUTPUT_DIR / "narrative_quality_checkpoint.jsonl"

# Matches a cited ATT&CK technique anywhere in prose (e.g. "process injection (T1055)").
_TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

# Synthesized evidence platform — fixtures model Windows PE families.
_SAMPLE_PLATFORM = "windows"
# How many of the report's techniques count toward coverage (top-N by definition
# of the synthesized bundle = all of them, but we cap for parity with the prompt
# which feeds the top 8 techniques to the narrator).
_COVERAGE_TOP_N = 8


# ---------------------------------------------------------------------------
# Fixed evidence builder
# ---------------------------------------------------------------------------


def _load_fixtures(limit: int) -> list[dict[str, Any]]:
    """Load fixture sample dicts (family + technique_ids). ``limit`` extends the
    set with ATT&CK-malware ground-truth files when it exceeds the 5 fixtures."""
    out: list[dict[str, Any]] = []
    for path in sorted(_FIXTURE_DIR.glob("*.json")):
        try:
            out.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    if limit and limit > len(out) and _GT_MALWARE_DIR.exists():
        extra = sorted(_GT_MALWARE_DIR.glob("*.json"))
        for path in extra:
            if len(out) >= limit:
                break
            try:
                rec = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if rec.get("technique_ids"):
                out.append(rec)
    if limit:
        return out[:limit]
    return out


def _category_for(fixture: dict[str, Any]) -> str:
    sid = str(fixture.get("sample_id", ""))
    for cat in ("ransomware", "rat", "dropper", "worm", "infostealer"):
        if cat in sid:
            return cat
    return "unknown"


def _build_report_from_fixture(
    fixture: dict[str, Any],
    name_map: dict[str, str] | None = None,
) -> MalwareReport:
    """Synthesize a deterministic ``MalwareReport`` carrying the fixture's
    techniques as ``ttp_mappings`` + ``capability_matrix``. This is the fixed,
    equal-budget evidence bundle both arms narrate. ``name_map`` (id -> ATT&CK
    name) is optional so the unit tests can build a report without the cache."""
    tids = [str(t) for t in (fixture.get("technique_ids") or []) if str(t)]
    name_map = name_map or {}
    category = _category_for(fixture)
    sample_id = str(fixture.get("sample_id", "synthetic"))

    ttp_mappings: list[TTPMapping] = []
    capability_matrix: list[CapabilityCell] = []
    for tid in tids:
        tname = name_map.get(tid, f"Technique {tid}")
        ttp_mappings.append(
            TTPMapping(
                technique_id=tid,
                technique_name=tname,
                evidence_quotes=[f"Sandbox + static evidence consistent with {tname} ({tid})."],
                confidence=0.7,
                contributing_layers=["dynamic", "static"],
                is_corroborated=True,
            )
        )
        capability_matrix.append(
            CapabilityCell(
                tactic="TA0002",
                tactic_name="Execution",
                technique_id=tid,
                technique_name=tname,
                evidence=[f"evidence for {tid}"],
                confidence=0.7,
                contributing_layers=["dynamic", "static"],
            )
        )

    return MalwareReport(
        verdict="Malware",
        overall_confidence=0.8,
        malware_category=category,
        severity=SeverityAssessment(
            overall_score=7.0, rating="High", affected_platforms=[_SAMPLE_PLATFORM]
        ),
        identity=SampleIdentity(
            hashes=FileHashes(sha256=("e" * 64)),
            file_name=f"{sample_id}.exe",
            file_type="PE32 executable",
            platform=_SAMPLE_PLATFORM,
        ),
        ttp_mappings=ttp_mappings,
        capability_matrix=capability_matrix,
        attribution=FamilyAttribution(family=category, family_confidence=0.8, family_grounded=True),
    )


# ---------------------------------------------------------------------------
# Scoring (pure functions — unit-tested without an LLM)
# ---------------------------------------------------------------------------


def _cited_technique_ids(exec_summary: str, capabilities: list[str]) -> set[str]:
    """Technique IDs cited anywhere in the narrative prose."""
    blob = " ".join([exec_summary, *capabilities])
    return {m.group(0).upper() for m in _TID_RE.finditer(blob)}


def _grounding_precision(cited: set[str], report_tids: set[str]) -> float:
    """Fraction of cited techniques that exist in the evidence (1.0 if none cited
    — vacuously faithful; the empty case is penalised by coverage instead)."""
    if not cited:
        return 1.0
    return len(cited & report_tids) / len(cited)


def _coverage_recall(cited: set[str], report_tids: set[str]) -> float:
    """Fraction of the evidence's techniques the narrative actually surfaces."""
    if not report_tids:
        return 1.0
    return len(cited & report_tids) / len(report_tids)


def _f1(precision: float, recall: float) -> float:
    if precision + recall <= 0.0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def _parenthesised_id_ratio(exec_summary: str, capabilities: list[str]) -> float:
    """Rule #2: every cited technique must appear with its ID in parentheses.
    Ratio of parenthesised ``(T1234)`` occurrences to total ID occurrences."""
    blob = " ".join([exec_summary, *capabilities])
    total = len(_TID_RE.findall(blob))
    if total == 0:
        return 1.0
    paren = len(re.findall(r"\(\s*T\d{4}(?:\.\d{3})?\s*\)", blob))
    return min(1.0, paren / total)


def _structural_pass(
    exec_summary: str,
    capabilities: list[str],
    n_recommendations: int,
) -> bool:
    """Schema/length/format compliance the NarrativeAgent prompt demands."""
    if not (120 <= len(exec_summary) <= 1200):
        return False
    if not (3 <= len(capabilities) <= 5):
        return False
    if not (3 <= n_recommendations <= 8):
        return False
    if _parenthesised_id_ratio(exec_summary, capabilities) < 1.0:
        return False
    return True


@dataclass
class NarrativeScore:
    grounding_precision: float
    coverage_recall: float
    f1: float
    structural_pass: bool
    linter_clean: bool
    n_cited: int
    n_hallucinated: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _score_from_dict(d: dict[str, Any]) -> NarrativeScore:
    return NarrativeScore(
        grounding_precision=float(d["grounding_precision"]),
        coverage_recall=float(d["coverage_recall"]),
        f1=float(d["f1"]),
        structural_pass=bool(d["structural_pass"]),
        linter_clean=bool(d["linter_clean"]),
        n_cited=int(d["n_cited"]),
        n_hallucinated=int(d["n_hallucinated"]),
    )


def score_narrative(
    *,
    report: MalwareReport,
    exec_summary: str,
    capabilities: list[str],
    n_recommendations: int,
) -> NarrativeScore:
    """Score one narrated report. ``report`` must already carry the narrative
    (so the fp_linter sees it). Pure given its inputs — no LLM, no network."""
    report_tids = {m.technique_id.upper() for m in report.ttp_mappings}
    capped = set(list(report_tids)[:_COVERAGE_TOP_N])
    cited = _cited_technique_ids(exec_summary, capabilities)
    precision = _grounding_precision(cited, report_tids)
    recall = _coverage_recall(cited, capped)
    warnings = lint_report(report, _SAMPLE_PLATFORM)
    clean = not any(w.rule in ("C2", "C3") for w in warnings)
    return NarrativeScore(
        grounding_precision=precision,
        coverage_recall=recall,
        f1=_f1(precision, recall),
        structural_pass=_structural_pass(exec_summary, capabilities, n_recommendations),
        linter_clean=clean,
        n_cited=len(cited),
        n_hallucinated=len(cited - report_tids),
    )


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


def _mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _bootstrap_ci(
    values: list[float],
    clusters: list | None = None,
    iters: int = 2000,
) -> tuple[float, float]:
    """95% bootstrap CI for the mean, resampling clusters.

    One record per sample here, so rows are clusters and the interval is
    unchanged by the migration; the reduction is pinned by a test.
    """
    vals = [float(v) for v in values]
    if len(vals) < 2:
        return (vals[0], vals[0]) if vals else (0.0, 0.0)
    keys = list(clusters) if clusters is not None else list(range(len(vals)))
    interval = stats.cluster_bootstrap_ci(vals, keys, iters=iters, seed=SEED)
    return (interval.lo, interval.hi)


# ---------------------------------------------------------------------------
# Arms
# ---------------------------------------------------------------------------


def _prose(rep: MalwareReport) -> dict[str, Any]:
    """The narrative text itself, kept alongside its score.

    §4.5 says retain enough to re-ask a question nobody has thought of yet.
    This harness scored prose for faithfulness and then discarded it, so a
    later question about the *same* generations — readability, redundancy,
    actionability — could not be put to them at all. That is the rule failing
    inside the harness that measures narrative quality, which is a good enough
    reason to keep the text and cheap enough to be no argument.
    """
    return {
        "executive_summary": rep.executive_summary,
        "capabilities_narrative": rep.capabilities_narrative,
        # Recommendations are model objects, not strings; dump them so the
        # checkpoint stays plain JSON that any later reader can open.
        "defensive_recommendations": [
            r.model_dump() if hasattr(r, "model_dump") else str(r)
            for r in (rep.defensive_recommendations or [])
        ],
    }


def _fallback_score(report: MalwareReport) -> tuple[NarrativeScore, dict[str, Any]]:
    """Deterministic baseline arm — apply the template narrative and score it."""
    rep = report.model_copy(deep=True)
    rep = MalwareReportBuilder.apply_fallback_narrative(rep)
    return (
        score_narrative(
            report=rep,
            exec_summary=rep.executive_summary,
            capabilities=rep.capabilities_narrative,
            n_recommendations=len(rep.defensive_recommendations),
        ),
        _prose(rep),
    )


async def _llm_score(
    narrative_agent: Any, report: MalwareReport
) -> tuple[NarrativeScore, dict[str, Any]] | None:
    """LLM arm — generate a narrative, apply it, and score. ``None`` on failure."""
    narrative = await narrative_agent.generate(report)
    if narrative is None:
        return None
    rep = report.model_copy(deep=True)
    rep = MalwareReportBuilder.apply_narrative(rep, narrative.model_dump())
    return (
        score_narrative(
            report=rep,
            exec_summary=rep.executive_summary,
            capabilities=rep.capabilities_narrative,
            n_recommendations=len(rep.defensive_recommendations),
        ),
        _prose(rep),
    )


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def _agg_block(title: str, scores: list[NarrativeScore]) -> list[str]:
    if not scores:
        return [f"## {title}", "", "_no samples_", ""]
    gp = [s.grounding_precision for s in scores]
    cr = [s.coverage_recall for s in scores]
    f1 = [s.f1 for s in scores]
    struct = [1.0 if s.structural_pass else 0.0 for s in scores]
    clean = [1.0 if s.linter_clean else 0.0 for s in scores]
    halluc = [float(s.n_hallucinated) for s in scores]

    def _row(label: str, xs: list[float]) -> str:
        lo, hi = _bootstrap_ci(xs)
        return f"| {label} | {_mean(xs):.3f} | [{lo:.3f}, {hi:.3f}] |"

    lines = [
        f"## {title} (n={len(scores)})",
        "",
        "| metric | mean | 95% bootstrap CI |",
        "|---|---|---|",
    ]
    lines.append(_row("grounding precision (faithfulness)", gp))
    lines.append(_row("coverage recall", cr))
    lines.append(_row("F1 (precision x recall)", f1))
    lines.append(_row("structural pass-rate", struct))
    lines.append(_row("fp_linter clean-rate (no C2/C3)", clean))
    lines.append(_row("hallucinated techniques (count)", halluc))
    lines.append("")
    return lines


def _paired_block(pairs: list[tuple[NarrativeScore, NarrativeScore]]) -> list[str]:
    """Paired LLM - fallback F1 deltas: bootstrap CI + sign test."""
    if not pairs:
        return ["## Paired (LLM - fallback, F1)", "", "_no paired samples_", ""]
    deltas = [llm.f1 - fb.f1 for llm, fb in pairs]
    wins = sum(1 for d in deltas if d > 1e-9)
    losses = sum(1 for d in deltas if d < -1e-9)
    ties = len(deltas) - wins - losses
    lo, hi = _bootstrap_ci(deltas)
    note = (
        "CI excludes 0 -> LLM narration differs from the template at this N."
        if (lo > 0 or hi < 0)
        else "CI crosses 0 -> not distinguishable from the template at this N."
    )
    return [
        "## Paired (LLM - fallback, F1)",
        "",
        f"- mean delta (LLM - fallback) = **{_mean(deltas):+.3f}**, "
        f"95% bootstrap CI [{lo:+.3f}, {hi:+.3f}] over n={len(deltas)} pairs.",
        f"- sign test: LLM wins {wins}, fallback wins {losses}, ties {ties}.",
        f"- {note}",
        "",
    ]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _attck_name_map() -> dict[str, str]:
    """Build an id -> name map from the cached ATT&CK bundle (empty on miss)."""
    try:
        from maljan.memory.attck_loader import load_attck_data

        data = load_attck_data()
        return {t.technique_id.upper(): t.name for t in data.techniques}
    except Exception as exc:  # noqa: BLE001
        print(f"ATT&CK name map unavailable ({exc}); using id placeholders.", flush=True)
        return {}


async def main_async(limit: int, repeats: int, smoke: bool, checkpoint: Path) -> None:
    fixtures = _load_fixtures(limit)
    if smoke:
        fixtures = fixtures[:1]
        repeats = 1
    if not fixtures:
        print("No fixtures found — aborting.", flush=True)
        return
    print(f"Loaded {len(fixtures)} sample(s); repeats={repeats}, smoke={smoke}.", flush=True)

    name_map = _attck_name_map()

    # Resume from checkpoint (keyed by sample_id:repeat).
    llm_scores: list[NarrativeScore] = []
    fb_scores: list[NarrativeScore] = []
    pairs: list[tuple[NarrativeScore, NarrativeScore]] = []
    done_keys: set[str] = set()
    if checkpoint.exists():
        for line in checkpoint.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            done_keys.add(rec["key"])
            if rec.get("llm"):
                ls = _score_from_dict(rec["llm"])
                llm_scores.append(ls)
                if rec.get("fallback"):
                    pairs.append((ls, _score_from_dict(rec["fallback"])))
            if rec.get("fallback"):
                fb_scores.append(_score_from_dict(rec["fallback"]))
        print(f"Resume: {len(done_keys)} generations already in {checkpoint}.", flush=True)

    container = ServiceContainer(get_settings(), mock=False)
    narrative_agent = container.get_narrative_agent()
    if narrative_agent is None:
        print("Narrative agent unavailable (mock mode / no LLM) — LLM arm skipped.", flush=True)
    else:
        # Eval-only: disable the local reasoning model's chain-of-thought so it
        # emits the narrative directly instead of spending the budget inside
        # <think> (stripped by the server -> empty output + timeouts). Set on the
        # ChatOpenAI field directly (not .bind) so with_structured_output still
        # works. Fail-safe if the provider doesn't expose the field.
        try:
            narrative_agent.llm.extra_body = {  # type: ignore[attr-defined]
                "chat_template_kwargs": {"enable_thinking": False}
            }
            narrative_agent.llm.request_timeout = 180  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass

    for fixture in fixtures:
        sid = str(fixture.get("sample_id", "synthetic"))
        report = _build_report_from_fixture(fixture, name_map)
        # Fallback is deterministic — score once per sample, reuse across repeats.
        fb, fb_prose = _fallback_score(report)
        for r in range(repeats):
            key = f"{sid}:{r}"
            if key in done_keys:
                continue
            llm: NarrativeScore | None = None
            llm_prose: dict[str, Any] | None = None
            if narrative_agent is not None:
                got = await _llm_score(narrative_agent, report)
                if got is not None:
                    llm, llm_prose = got
            fb_scores.append(fb)
            if llm is not None:
                llm_scores.append(llm)
                pairs.append((llm, fb))
            with checkpoint.open("a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps(
                        {
                            "key": key,
                            "sample_id": sid,
                            "llm": llm.to_dict() if llm else None,
                            "fallback": fb.to_dict(),
                            "llm_prose": llm_prose,
                            "fallback_prose": fb_prose,
                        }
                    )
                    + "\n"
                )
            print(f"  {key}: llm={'ok' if llm else 'skip'} fallback=ok", flush=True)

    lines = [
        "# Narrative-quality evaluation (LLM vs deterministic fallback)",
        "",
        "- Faithfulness-centric metrics (no human reference prose vendored): grounding",
        "  precision = cited techniques present in the evidence; coverage recall = evidence",
        "  techniques surfaced; structural = schema/length/parenthesised-ID compliance;",
        "  fp_linter clean = no C2 (recommendation cites absent technique) / C3 (exec-summary",
        "  platform mismatch). F1 = harmonic mean of precision and recall.",
        f"- Samples generated {repeats}x each for N>>1 (decoding variance -> bootstrap CI).",
        "",
    ]
    lines += _agg_block("LLM narrative", llm_scores)
    lines += _agg_block("Deterministic fallback", fb_scores)
    lines += _paired_block(pairs)
    report_md = "\n".join(lines)
    print("\n" + report_md, flush=True)
    try:
        _OUT_FILE.write_text(report_md + "\n", encoding="utf-8")
        print(f"\nWrote {_OUT_FILE}", flush=True)
    except OSError:
        pass


def main() -> None:
    ap = argparse.ArgumentParser(description="MaLAware-style narrative-quality eval.")
    ap.add_argument("--limit", type=int, default=0, help="Sample cap (0 = the 5 fixtures).")
    ap.add_argument("--repeats", type=int, default=3, help="LLM generations per sample (N>>1).")
    ap.add_argument("--smoke", action="store_true", help="1 sample x 1 repeat end-to-end check.")
    ap.add_argument("--checkpoint", type=str, default=str(_DEFAULT_CHECKPOINT))
    args = ap.parse_args()
    asyncio.run(main_async(args.limit, args.repeats, args.smoke, Path(args.checkpoint)))


if __name__ == "__main__":
    main()
