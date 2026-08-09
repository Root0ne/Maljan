"""B2 — does the confidence number this system runs on predict correctness?

`arXiv:2606.29490` (Kumaran et al.) finds that an LLM's **verbally reported**
confidence tracks its *readiness to commit*, not whether it is right, while
calibrated log-probabilities do track correctness. That is not an abstract worry
here: `ClaimEvidence.confidence` is a self-reported number, every ISR claim
carries one, and the cascade consumes it. If it does not separate correct claims
from wrong ones, then every deterministic gate in this pipeline is load-bearing
in a way we have been treating as belt-and-braces — and §1.10's finding that the
cascade *weights* move almost nothing points the same way.

**This is an extension, not a replication.** Q1 read Kumaran in full: their suite
is MCQ and open-ended QA (SimpleQA, MMLU-Pro, SuperGPQA-hard, HLE), with **no
structured or evidence-cited outputs**. Ours are structured claims that must cite
an artifact. Whether the finding survives that shift is the open question, and it
is worth reporting either way.

Metrics, all computed from the same (confidence, correct) pairs:

  * **AUC** — P(a correct claim is scored above a wrong one), ties at 0.5. The
    direct answer to "does the number rank correctness at all".
  * **separation** — mean confidence on correct minus mean on wrong, the same
    shape as §1.5.1's gate-separation metric so the two are readable together.
  * **ECE** and **Brier** — whether the number is *calibrated*, not merely
    ordered. A model can rank well and still be uniformly overconfident, which is
    exactly what `arXiv:2503.23175` reports for CTI.

Two reporting rules that exist to stop a comfortable non-result:

  * AUC is **None**, not 0.5, when one class is empty. Returning 0.5 would
    manufacture a tidy "no discrimination" finding out of missing data.
  * claims with no ``technique_id`` cannot be scored against a technique set, so
    they are excluded **and counted**. Silently dropping them would bias the
    sample toward whatever the model is willing to name.

Run:  uv run python tests/evaluation/eval_confidence_calibration.py
      [--repeats K] [--budget B] [--smoke]
Requires a live llama-server. Pure helpers unit-tested in
``test_confidence_calibration_scoring.py``.
"""

# Bootstraps sys.path before first-party imports (E402 is intentional here).
# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
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
from tests.evaluation.eval_consensus_ablation import (
    CHANNELS,
    bootstrap_ci,
    build_channels,
    channel_prompt,
    leaked_ids,
    load_samples,
    mean,
    per_call_budget,
)

_OUT_FILE = _REPO_ROOT / "tests" / "evaluation" / "confidence_calibration.md"
_JSON_FILE = _REPO_ROOT / "tests" / "evaluation" / "confidence_calibration.json"
_DEFAULT_CHECKPOINT = Path("/tmp/confidence_calibration_checkpoint.jsonl")
_DEFAULT_BUDGET = 800


# ---------------------------------------------------------------------------
# Metrics (pure — unit-tested without an LLM)
# ---------------------------------------------------------------------------


def roc_auc(scores: list[float], labels: list[int]) -> float | None:
    """P(a positive outranks a negative), ties counted as 0.5.

    Returns **None** when either class is empty — the value is undefined, and
    returning 0.5 would present missing data as a measured "no discrimination"
    result. Pairwise rather than rank-based: n is small here and the pairwise
    form is obviously correct about ties, which is where AUC implementations
    usually go wrong.
    """
    pos = [s for s, y in zip(scores, labels, strict=True) if y == 1]
    neg = [s for s, y in zip(scores, labels, strict=True) if y == 0]
    if not pos or not neg:
        return None
    total = 0.0
    for p in pos:
        for n in neg:
            if p > n:
                total += 1.0
            elif p == n:
                total += 0.5
    return total / (len(pos) * len(neg))


def separation(scores: list[float], labels: list[int]) -> float | None:
    """Mean confidence on correct claims minus mean on wrong ones.

    Deliberately the same shape as §1.5.1's gate-separation metric so the two
    numbers can be read side by side. None when either class is empty.
    """
    pos = [s for s, y in zip(scores, labels, strict=True) if y == 1]
    neg = [s for s, y in zip(scores, labels, strict=True) if y == 0]
    if not pos or not neg:
        return None
    return mean(pos) - mean(neg)


def brier_score(scores: list[float], labels: list[int]) -> float:
    """Mean squared error between stated confidence and outcome. Lower is better."""
    if not scores:
        return 0.0
    return mean([(s - y) ** 2 for s, y in zip(scores, labels, strict=True)])


def reliability_bins(
    scores: list[float], labels: list[int], n_bins: int = 5
) -> list[tuple[float, float, float, int]]:
    """Reliability curve: ``(bin_lo, bin_hi, observed_accuracy, count)`` per bin.

    Empty bins are omitted rather than reported as accuracy 0 — an unvisited
    confidence band is not a band where the model is always wrong.
    """
    if not scores or n_bins < 1:
        return []
    width = 1.0 / n_bins
    out: list[tuple[float, float, float, int]] = []
    for i in range(n_bins):
        lo = i * width
        hi = 1.0 if i == n_bins - 1 else (i + 1) * width
        # Upper-closed on the last bin only, so confidence 1.0 has a home.
        members = [
            y
            for s, y in zip(scores, labels, strict=True)
            if (lo <= s < hi) or (i == n_bins - 1 and s == 1.0)
        ]
        if members:
            out.append((lo, hi, mean([float(m) for m in members]), len(members)))
    return out


def expected_calibration_error(scores: list[float], labels: list[int], n_bins: int = 5) -> float:
    """Weighted mean gap between stated confidence and observed accuracy per bin.

    Ordering and calibration are different questions: a model can rank
    correctness well (high AUC) and still be uniformly overconfident (high ECE),
    which is what `arXiv:2503.23175` reports for LLMs on real CTI reports.
    """
    if not scores:
        return 0.0
    total = 0.0
    for lo, hi, accuracy, count in reliability_bins(scores, labels, n_bins):
        members = [s for s in scores if (lo <= s < hi) or (hi == 1.0 and s == 1.0)]
        if not members:
            continue
        total += (count / len(scores)) * abs(mean(members) - accuracy)
    return total


def overconfidence(scores: list[float], labels: list[int]) -> float:
    """Mean stated confidence minus observed accuracy. Positive = overconfident.

    The single number `arXiv:2503.23175` and Kumaran both report; kept separate
    from ECE because ECE cannot tell over- from under-confidence.
    """
    if not scores:
        return 0.0
    return mean(scores) - mean([float(y) for y in labels])


@dataclass
class ClaimScore:
    sample_id: str
    channel: str
    repeat: int
    technique_id: str
    confidence: float
    correct: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def score_from_dict(d: dict[str, Any]) -> ClaimScore:
    return ClaimScore(
        sample_id=str(d["sample_id"]),
        channel=str(d["channel"]),
        repeat=int(d["repeat"]),
        technique_id=str(d["technique_id"]),
        confidence=float(d["confidence"]),
        correct=int(d["correct"]),
    )


def score_claims(
    claims: list[Any], truth: list[str], *, sample_id: str, channel: str, repeat: int
) -> tuple[list[ClaimScore], int]:
    """Turn one ISR's claims into scored rows. Returns ``(rows, unscoreable)``.

    A claim with no ``technique_id`` cannot be checked against a technique set.
    It is excluded and **counted**, because dropping it silently would bias the
    sample toward the claims the model was willing to name.
    """
    tset = {t.upper() for t in truth}
    rows: list[ClaimScore] = []
    unscoreable = 0
    for c in claims:
        tid = str(getattr(c, "technique_id", "") or "").strip().upper()
        if not tid:
            unscoreable += 1
            continue
        conf = getattr(c, "confidence", None)
        if conf is None:
            unscoreable += 1
            continue
        rows.append(
            ClaimScore(
                sample_id=sample_id,
                channel=channel,
                repeat=repeat,
                technique_id=tid,
                confidence=float(conf),
                correct=1 if tid in tset else 0,
            )
        )
    return rows, unscoreable


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def _fmt(value: float | None, spec: str = ".3f") -> str:
    return "—" if value is None else f"{value:{spec}}"


def summary_block(title: str, rows: list[ClaimScore]) -> list[str]:
    if not rows:
        return [f"## {title}", "", "_no scoreable claims_", ""]
    scores = [r.confidence for r in rows]
    labels = [r.correct for r in rows]
    auc = roc_auc(scores, labels)
    sep = separation(scores, labels)
    lo, hi = bootstrap_ci(scores)
    n_pos = sum(labels)
    lines = [
        f"## {title}  (n={len(rows)} claims, {n_pos} correct / {len(rows) - n_pos} wrong)",
        "",
        "| metric | value |",
        "|---|---|",
        f"| **AUC** (does confidence rank correctness?) | **{_fmt(auc)}** |",
        f"| **separation** (mean correct − mean wrong) | **{_fmt(sep, '+.3f')}** |",
        f"| accuracy | {mean([float(x) for x in labels]):.3f} |",
        f"| mean stated confidence | {mean(scores):.3f} [{lo:.3f}, {hi:.3f}] |",
        f"| overconfidence (stated − actual) | {overconfidence(scores, labels):+.3f} |",
        f"| ECE (5 bins) | {expected_calibration_error(scores, labels):.3f} |",
        f"| Brier | {brier_score(scores, labels):.3f} |",
        "",
    ]
    bins = reliability_bins(scores, labels)
    if bins:
        lines += ["| confidence bin | observed accuracy | n |", "|---|---|---|"]
        lines += [f"| [{lo_:.1f}, {hi_:.1f}) | {acc:.3f} | {cnt} |" for lo_, hi_, acc, cnt in bins]
        lines += [""]
    return lines


def verdict_lines(rows: list[ClaimScore]) -> list[str]:
    """State what the numbers mean for the cascade, in the honest direction."""
    if not rows:
        return []
    auc = roc_auc([r.confidence for r in rows], [r.correct for r in rows])
    if auc is None:
        return [
            "**Undefined.** One class is empty — every scoreable claim was correct, or none was.",
            "AUC is not reported as 0.5 here; that would present missing data as a measurement.",
            "",
        ]
    if auc < 0.60:
        return [
            f"**The reported confidence barely ranks correctness (AUC {auc:.3f}).** This",
            "replicates `arXiv:2606.29490` in a setting it did not test — structured,",
            "evidence-cited claims — and it justifies every deterministic gate downstream:",
            "a number that does not separate right from wrong cannot be the thing the",
            "cascade trusts. Converges with §1.10, where the cascade weights moved the",
            "corroborated set on 0.0% of samples.",
            "",
        ]
    return [
        f"**Confidence does carry signal here (AUC {auc:.3f}).** That is a *negative* result",
        "for the extension: Kumaran's finding does not transfer unchanged to structured,",
        "evidence-cited claims. Report it as such — the deterministic gates then need a",
        "justification other than 'the confidence number is meaningless'.",
        "",
    ]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main_async(repeats: int, budget: int, smoke: bool, checkpoint: Path) -> None:
    samples = load_samples()
    built = [(sid, tids, build_channels(tids)) for sid, tids in samples]
    for sid, _tids, channels in built:
        leaks = leaked_ids(channels)
        if leaks:
            print(f"ABORT: {sid} leaks ground-truth ids into evidence: {leaks}", flush=True)
            return
    if smoke:
        built = built[:1]
        repeats = 1
    if not built:
        print("No fixtures found — aborting.", flush=True)
        return

    rows: list[ClaimScore] = []
    done: set[str] = set()
    unscoreable_total = 0
    if checkpoint.exists():
        for line in checkpoint.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                done.add(rec["key"])
                rows.append(score_from_dict(rec))
        print(f"Resume: {len(done)} claims in {checkpoint}.", flush=True)

    container = ServiceContainer(get_settings(), mock=False)
    agent = container.get_agent("static")
    try:
        agent.llm.request_timeout = 180  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass
    try:
        agent.llm = agent.llm.bind(  # type: ignore[attr-defined]
            extra_body={"chat_template_kwargs": {"enable_thinking": False}}
        )
    except Exception:  # noqa: BLE001
        pass

    per_call = per_call_budget(budget, 1)
    print(
        f"{len(built)} sample(s), channels={list(CHANNELS)}, repeats={repeats}, "
        f"budget/call={per_call}.",
        flush=True,
    )

    for sid, truth, channels in built:
        for r in range(repeats):
            for channel in CHANNELS:
                if channel not in channels:
                    continue
                key = f"{sid}:{channel}:{r}"
                if key in done:
                    continue
                try:
                    text = agent._invoke_view(channel_prompt(channel), channels[channel], per_call)
                    isr = agent._text_to_isr(text, revision_round=0)
                except Exception as exc:  # noqa: BLE001 — one decode must not kill the batch
                    print(f"  SKIP {key}: {type(exc).__name__}: {exc}", flush=True)
                    continue
                scored, unscoreable = score_claims(
                    isr.claims, truth, sample_id=sid, channel=channel, repeat=r
                )
                unscoreable_total += unscoreable
                with checkpoint.open("a", encoding="utf-8") as fh:
                    for row in scored:
                        fh.write(json.dumps({"key": key, **row.to_dict()}) + "\n")
                rows.extend(scored)
                n_ok = sum(s.correct for s in scored)
                print(
                    f"  {key}: {len(scored)} scoreable ({n_ok} correct), {unscoreable} unscoreable",
                    flush=True,
                )

    lines = [
        "# B2 — does verbal confidence predict correctness?",
        "",
        "`arXiv:2606.29490` finds reported confidence tracks readiness to commit rather than",
        "correctness — on MCQ and open-ended QA. This is the **extension** to structured,",
        "evidence-cited claims, which that suite did not cover.",
        "",
        f"- **{unscoreable_total} claim(s) carried no technique id or no confidence** and are",
        "  excluded from every number below. They are counted rather than dropped silently:",
        "  omitting them would bias the sample toward claims the model was willing to name.",
        "- AUC is reported as `—` rather than 0.5 when a class is empty.",
        "",
    ]
    lines += summary_block("All channels", rows)
    lines += verdict_lines(rows)
    for channel in CHANNELS:
        subset = [r for r in rows if r.channel == channel]
        if subset:
            lines += summary_block(f"Channel: {channel}", subset)

    report = "\n".join(lines)
    print("\n" + report, flush=True)
    try:
        _OUT_FILE.write_text(report + "\n", encoding="utf-8")
        _JSON_FILE.write_text(
            json.dumps([r.to_dict() for r in rows], indent=2) + "\n", encoding="utf-8"
        )
        print(f"\nWrote {_OUT_FILE} and {_JSON_FILE}", flush=True)
    except OSError as exc:
        print(f"Could not write report: {exc}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="B2 verbal-confidence calibration.")
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--budget", type=int, default=_DEFAULT_BUDGET)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument("--checkpoint", type=Path, default=_DEFAULT_CHECKPOINT)
    args = ap.parse_args()
    main_async(args.repeats, args.budget, args.smoke, args.checkpoint)


if __name__ == "__main__":
    main()
