"""View-decomposition A/B: monolithic vs N-view, done to the findings-log §3.4 bar.

findings-log §3.2 probed AppPoet-style view-decomposition and was ruled
INCONCLUSIVE because the arms had **unequal total generation budget** (a 4-view
run got ~5x monolithic's tokens), claim-count is a poor proxy, and the monolithic
arm hallucinated an invalid technique id under a big budget. This harness redoes
the study correctly:

  * **Equal total budget** — every arm gets the same total output budget B.
    Monolithic = 1 call at B; N-view = N calls at B/N each. This removes the §3.2
    confound (the whole reason it was inconclusive).
  * **N >> 1** — each (sample, arm) is generated ``--repeats K`` times; we report
    mean +/- bootstrap CI, and the claim-count *stability* (stdev) across repeats —
    the budget-independent property §3.2 found defensible.
  * **Correctness, not count** — we score the **invalid/hallucinated technique-id
    rate** (via the production ATT&CK validator — the T1000 failure mode) and a
    grounding rate (claim cites an artifact present in the evidence), not raw count.
  * **Same tools-free text path** — both arms call ``BaseAnalyst._invoke_view`` so
    the only variable is monolithic-vs-decomposed.

Run:  uv run python tests/evaluation/eval_view_decomposition.py [--repeats K] [--budget B] [--smoke]
Requires a live llama-server. Measurement tool, not a pytest test (the pure
scoring helpers are unit-tested in ``test_view_decomposition_scoring.py``).
"""

# Bootstraps sys.path before first-party imports (E402 is intentional here).
# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from maljan.core.config import get_settings
from maljan.core.container import ServiceContainer
from tests.evaluation import stats  # noqa: E402

# No seed constant existed here: the estimator hard-coded one in its body
# and wrote none into the artifact, so a published interval could not be
# reproduced from its own file. Dated to dated to the run that produced the view-decomposition arms.
SEED = 20260809

_FIXTURE_DIR = _REPO_ROOT / "tests" / "evaluation" / "fixtures"
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
_OUT_FILE = _OUTPUT_DIR / "view_decomposition.md"
_DEFAULT_CHECKPOINT = _OUTPUT_DIR / "view_decomposition_checkpoint.jsonl"
_DEFAULT_BUDGET = 2000

_TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

# Monolithic arm instruction — analyse every facet in one call (full budget).
_ALL_INSTRUCTION = (
    "Analyse the sample across ALL facets: executable behaviour, static artifacts, "
    "persistence, network/C2, cryptography/obfuscation, and anti-analysis/evasion. "
    "Report every finding the evidence supports."
)


# ---------------------------------------------------------------------------
# Evidence bundles
# ---------------------------------------------------------------------------


def _load_bundles() -> list[tuple[str, str]]:
    """Build balanced text evidence bundles from the fixtures (id, bundle_text)."""
    bundles: list[tuple[str, str]] = []
    for path in sorted(_FIXTURE_DIR.glob("*.json")):
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        sid = str(rec.get("sample_id", path.stem))
        bundles.append((sid, _bundle_text(rec)))
    return bundles


def _bundle_text(rec: dict[str, Any]) -> str:
    """Synthesize a balanced evidence bundle referencing concrete artifacts so
    both grounding and the per-view focus have material to work with."""
    notes = str(rec.get("notes", ""))
    tids = [str(t) for t in (rec.get("technique_ids") or [])]
    lines = [f"Sample behaviour summary: {notes}", "", "Observed evidence:"]
    # A few concrete, technique-anchored artifacts (deterministic).
    artifacts = [
        "API call: CreateRemoteThread in target process explorer.exe (PID 1234)",
        "Registry key set: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        "Dropped file: C:\\Users\\Public\\stage2.bin (high entropy)",
        "Network flow: TLS to 185.220.101.47:443, SNI cdn.example-c2.top",
        "DNS query: kq3x9zjptlvbq.duckdns.org (algorithmic label)",
        "String: 'CryptAcquireContextW' near .data+0x40",
    ]
    for i, tid in enumerate(tids):
        art = artifacts[i % len(artifacts)]
        lines.append(f"- {art}  [associated technique: {tid}]")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Scoring (pure functions — unit-tested without an LLM)
# ---------------------------------------------------------------------------


def _cited_tids(claims: list[Any]) -> list[str]:
    """All technique ids cited across an ISR's claims (claim text + field)."""
    out: list[str] = []
    for c in claims:
        if getattr(c, "technique_id", None):
            out.append(str(c.technique_id).upper())
        out.extend(m.group(0).upper() for m in _TID_RE.finditer(str(getattr(c, "claim", ""))))
    return out


def _invalid_id_rate(tids: list[str], is_valid: Callable[[str], bool]) -> float:
    """Fraction of cited technique ids that are NOT valid ATT&CK ids (the §3.2
    hallucination failure mode). 0.0 when nothing is cited."""
    if not tids:
        return 0.0
    bad = sum(1 for t in tids if not is_valid(t))
    return bad / len(tids)


def _grounding_rate(claims: list[Any], bundle_text: str) -> float:
    """Fraction of claims that reference an artifact present in the evidence.

    A claim is grounded when its technique id appears in the bundle, or its
    evidence_ref shares a substantive token (len>=4) with the bundle text."""
    if not claims:
        return 1.0
    blob = bundle_text.lower()
    grounded = 0
    for c in claims:
        tid = str(getattr(c, "technique_id", "") or "").upper()
        ref = str(getattr(c, "evidence_ref", "") or "").lower()
        tokens = [t for t in re.split(r"[^a-z0-9]+", ref) if len(t) >= 4]
        if (tid and tid in bundle_text.upper()) or any(t in blob for t in tokens):
            grounded += 1
    return grounded / len(claims)


def _mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _stability(counts: list[int]) -> float:
    """Population standard deviation of claim counts across repeats (lower =
    more stable). The budget-independent property §3.2 found defensible."""
    if len(counts) < 2:
        return 0.0
    m = _mean([float(c) for c in counts])
    var = sum((c - m) ** 2 for c in counts) / len(counts)
    return var**0.5


def _bootstrap_ci(
    values: list[float],
    clusters: list | None = None,
    iters: int = 2000,
) -> tuple[float, float]:
    """95% bootstrap CI for the mean, resampling clusters.

    Arm metric values, one per sample. Rows are clusters.
    """
    vals = [float(v) for v in values]
    if len(vals) < 2:
        return (vals[0], vals[0]) if vals else (0.0, 0.0)
    keys = list(clusters) if clusters is not None else list(range(len(vals)))
    interval = stats.cluster_bootstrap_ci(vals, keys, iters=iters, seed=SEED)
    return (interval.lo, interval.hi)


@dataclass
class ArmScore:
    arm: str
    sample_id: str
    repeat: int
    claim_count: int
    invalid_id_rate: float
    grounding_rate: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _score_from_dict(d: dict[str, Any]) -> ArmScore:
    return ArmScore(
        arm=str(d["arm"]),
        sample_id=str(d["sample_id"]),
        repeat=int(d["repeat"]),
        claim_count=int(d["claim_count"]),
        invalid_id_rate=float(d["invalid_id_rate"]),
        grounding_rate=float(d["grounding_rate"]),
    )


# ---------------------------------------------------------------------------
# Arms (live LLM)
# ---------------------------------------------------------------------------


def _run_monolithic(agent: Any, bundle: str, budget: int) -> Any:
    """One full-budget tools-free call analysing every facet."""
    text = agent._invoke_view(_ALL_INSTRUCTION, bundle, budget or None)
    return agent._text_to_isr(text, revision_round=0)


def _run_nview(agent: Any, bundle: str, n: int, budget: int) -> Any:
    """N equal-budget (B/N) focused views, merged."""
    return agent.analyze_isr_views(bundle, n, total_max_tokens=budget or None)


def _run_tiered(agent: Any, bundle: str, n: int, budget: int) -> Any:
    """N equal-budget (B/N) SEQUENTIAL reasoning tiers (LAMD, §4 Item 3), merged."""
    return agent.analyze_isr_tiered(bundle, n, total_max_tokens=budget or None)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def _arm_block(arm: str, scores: list[ArmScore], budget: int, n_calls: int) -> list[str]:
    if not scores:
        return [f"## {arm}", "", "_no samples_", ""]
    counts = [s.claim_count for s in scores]
    inval = [s.invalid_id_rate for s in scores]
    ground = [s.grounding_rate for s in scores]
    # Stability per sample (stdev of claim count across repeats), then averaged.
    by_sample: dict[str, list[int]] = {}
    for s in scores:
        by_sample.setdefault(s.sample_id, []).append(s.claim_count)
    stab = _mean([_stability(v) for v in by_sample.values()])

    def _row(label: str, xs: list[float]) -> str:
        lo, hi = _bootstrap_ci(xs)
        return f"| {label} | {_mean(xs):.3f} | [{lo:.3f}, {hi:.3f}] |"

    per_call = budget // max(n_calls, 1)
    return [
        f"## {arm}  (n={len(scores)}, calls/sample={n_calls}, budget/call={per_call})",
        "",
        "| metric | mean | 95% bootstrap CI |",
        "|---|---|---|",
        _row("claim count", [float(c) for c in counts]),
        _row("invalid technique-id rate", inval),
        _row("grounding rate", ground),
        f"| claim-count stability (stdev, lower=better) | {stab:.3f} | — |",
        "",
    ]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main_async(
    repeats: int,
    budget: int,
    views: list[int],
    tiers: list[int],
    smoke: bool,
    checkpoint: Path,
) -> None:
    from maljan.memory.attck_validator import ATTCKValidator

    bundles = _load_bundles()
    if smoke:
        bundles = bundles[:1]
        repeats = 1
        views = views[:1]
        tiers = tiers[:1]
    if not bundles:
        print("No fixtures found — aborting.", flush=True)
        return

    try:
        validator = ATTCKValidator.get_instance()
        is_valid = validator.validate_ttp_id
    except Exception as exc:  # noqa: BLE001
        print(f"ATT&CK validator unavailable ({exc}); invalid-id rate disabled.", flush=True)

        def is_valid(_tid: str) -> bool:
            return True

    arms = ["monolithic"] + [f"{n}-view" for n in views] + [f"{n}-tier" for n in tiers]
    print(f"{len(bundles)} sample(s), arms={arms}, repeats={repeats}, budget={budget}.", flush=True)

    scores: list[ArmScore] = []
    done: set[str] = set()
    if checkpoint.exists():
        for line in checkpoint.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                done.add(rec["key"])
                scores.append(_score_from_dict(rec))
        print(f"Resume: {len(done)} generations in {checkpoint}.", flush=True)

    container = ServiceContainer(get_settings(), mock=False)
    agent = container.get_agent("static")
    # Eval-only, applied identically to every arm so the equal-budget A/B stays
    # fair. See ``eval_consensus_ablation.bind_eval_llm`` for why the timeout has
    # to be a per-request bind kwarg.
    #
    # 2026-08-09 CORRECTION. This block previously did
    # ``agent.llm.request_timeout = 180`` and a comment claiming it made a stuck
    # decode "fail fast". **It did not.** ChatOpenAI builds its HTTP client at
    # construction from request_timeout — 1800 s here (llm/openai_provider.py) —
    # and assigning the attribute afterwards never rebuilds that client, so the
    # cap was inert. Found while B1 sat 14+ minutes on one call under a "180 s"
    # cap. The §3.6 numbers stand: the timeout was a convenience for aborting
    # bad decodes, not a measurement parameter, and every arm shared whatever
    # ceiling was really in force. What was wrong was the comment.
    from tests.evaluation.eval_consensus_ablation import bind_eval_llm

    bind_eval_llm(agent)

    def _record(arm: str, sid: str, r: int, isr: Any, bundle: str) -> None:
        tids = _cited_tids(isr.claims)
        sc = ArmScore(
            arm=arm,
            sample_id=sid,
            repeat=r,
            claim_count=len(isr.claims),
            invalid_id_rate=_invalid_id_rate(tids, is_valid),
            grounding_rate=_grounding_rate(isr.claims, bundle),
        )
        scores.append(sc)
        with checkpoint.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"key": f"{arm}:{sid}:{r}", **sc.to_dict()}) + "\n")
        print(
            f"  {arm}:{sid}:{r} claims={sc.claim_count} inval={sc.invalid_id_rate:.2f}", flush=True
        )

    def _run_arm(arm: str, sid: str, r: int, bundle: str) -> None:
        """Run one (arm, sample, repeat) generation; skip-and-log on failure.

        A single timed-out / degenerate decode must not abort the multi-hour
        batch — the checkpoint preserves everything already done, so a skipped
        generation just lowers that arm's n for this run.
        """
        if f"{arm}:{sid}:{r}" in done:
            return
        try:
            if arm == "monolithic":
                isr = _run_monolithic(agent, bundle, budget)
            elif arm.endswith("-view"):
                isr = _run_nview(agent, bundle, int(arm.split("-")[0]), budget)
            else:  # "-tier"
                isr = _run_tiered(agent, bundle, int(arm.split("-")[0]), budget)
        except Exception as exc:  # noqa: BLE001 — one bad decode must not kill the batch
            print(f"  SKIP {arm}:{sid}:{r}: {type(exc).__name__}: {exc}", flush=True)
            return
        _record(arm, sid, r, isr, bundle)

    for sid, bundle in bundles:
        for r in range(repeats):
            for arm in arms:
                _run_arm(arm, sid, r, bundle)

    lines = [
        "# View-decomposition A/B (equal total budget, §3.4-compliant)",
        "",
        "- Every arm gets the same total output budget B; N-view splits it B/N per call.",
        "- Metrics: claim count, invalid technique-id rate (hallucination), grounding rate,",
        "  and claim-count stability (stdev across repeats). Mean ± 95% bootstrap CI.",
        "",
    ]
    lines += _arm_block("monolithic", [s for s in scores if s.arm == "monolithic"], budget, 1)
    for n in views:
        lines += _arm_block(f"{n}-view", [s for s in scores if s.arm == f"{n}-view"], budget, n)
    for n in tiers:
        lines += _arm_block(f"{n}-tier", [s for s in scores if s.arm == f"{n}-tier"], budget, n)
    report = "\n".join(lines)
    print("\n" + report, flush=True)
    try:
        _OUT_FILE.write_text(report + "\n", encoding="utf-8")
        print(f"\nWrote {_OUT_FILE}", flush=True)
    except OSError:
        pass


def main() -> None:
    ap = argparse.ArgumentParser(description="View-decomposition equal-budget A/B.")
    ap.add_argument("--repeats", type=int, default=3, help="Generations per (sample, arm).")
    ap.add_argument("--budget", type=int, default=_DEFAULT_BUDGET, help="Total output budget B.")
    ap.add_argument("--views", type=str, default="2,4", help="Comma list of facet view counts.")
    ap.add_argument(
        "--tiers",
        type=str,
        default="3",
        help="Comma list of sequential reasoning-tier counts (LAMD, §4 Item 3).",
    )
    ap.add_argument("--smoke", action="store_true", help="1 sample x 1 repeat x first arm.")
    ap.add_argument("--checkpoint", type=str, default=str(_DEFAULT_CHECKPOINT))
    args = ap.parse_args()
    views = [int(x) for x in str(args.views).split(",") if x.strip()]
    tiers = [int(x) for x in str(args.tiers).split(",") if x.strip()]
    main_async(args.repeats, args.budget, views, tiers, args.smoke, Path(args.checkpoint))


if __name__ == "__main__":
    main()
