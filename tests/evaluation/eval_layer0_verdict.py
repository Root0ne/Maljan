"""B3 + B4 — does removing a deterministic layer change the *verdict*, and what does the
STIX integrity pass actually do?

Two questions share one harness because they share one expensive step: a judge
call over a controlled evidence set.

**B3 (→ E.5).** §1.10 measured what the static Layer-0 sources contribute *to the
cascade arithmetic*: perturbing the layer weights moved the top-10 ranking on
10.6–27.5% of samples and the corroborated set on **0.0%**, because
``is_corroborated`` never consults the weights. That is a statement about the
cascade, not about the system. The question left open is the one that matters
operationally: **does removing a whole layer change the bundle the analyst
receives?** A layer can be arithmetically load-bearing and still change nothing
downstream, or the reverse.

**B4 (→ C7).** C7 claims that repairing a malformed bundle beats rejecting it.
That is a design claim until someone counts how often the integrity pass fires
and what it removes. A3 instrumented the pass; this is the run that reads the
counters, on **fresh** bundles — the archived ones predate the `spec_version`
fix and the defect classes come from LLM generation.

Design. For each fixture the ground-truth techniques are distributed across the
three static Layer-0 sources, ISRs are synthesised **deterministically**, the
cascade runs over them, and the judge produces a bundle. Arms remove one source
at a time. The only variable is which layer exists.

  all · no_yara_layer · no_import_capability_layer · no_tool_artifact_layer

**Pre-registered predictions, from §1.10 and from the domain map:**
  1. ``tool_artifact_layer`` shares **yara's cascade domain**, so removing it
     cannot change corroboration for any technique yara also covers — only the
     techniques it uniquely carries can move.
  2. §1.10 found the corroborated set structurally insensitive to weights. If it
     is *also* insensitive to whole-layer removal, the cascade's trust model is
     doing far less than the architecture claims for it, and that is the finding.

**A scope limit stated up front, because it bounds what B3 can conclude.** Here
each source carries an equal share of the ground truth by construction. In
production the rates are wildly uneven — §1.10 measured yara firing on 89.5% of
samples, import-capability on 52.6% and tool-artifact on **2.4%** (5 techniques
across the whole corpus). So this harness measures the **mechanism** (does layer
removal propagate to the verdict at a controlled contribution level); it does
**not** estimate the real-world impact of removing a layer. That needs C2's
measured rates, and the two must be read together.

Run:  uv run python tests/evaluation/eval_layer0_verdict.py [--repeats K] [--smoke]
Requires a live llama-server. Pure helpers unit-tested in
``test_layer0_verdict_scoring.py``.
"""

# Bootstraps sys.path before first-party imports (E402 is intentional here).
# ruff: noqa: E402

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from maljan.core.config import get_settings
from maljan.core.container import ServiceContainer
from maljan.core.truncation_ledger import TruncationLedger
from tests.evaluation.eval_consensus_ablation import (
    bind_eval_llm,
    bootstrap_ci,
    load_samples,
    mean,
)

_OUT_FILE = _REPO_ROOT / "tests" / "evaluation" / "layer0_verdict.md"
_JSON_FILE = _REPO_ROOT / "tests" / "evaluation" / "layer0_verdict.json"
_DEFAULT_CHECKPOINT = Path("/tmp/layer0_verdict_checkpoint.jsonl")

# All six Layer-0 sources, with the cascade domain each actually emits on, taken
# from the production layers rather than assumed. tool_artifact sharing yara's
# domain is not an accident of this harness -- it is what the production layer
# does (src/maljan/analysis/tool_artifact_layer.py), and it is why §1.10 found
# that source unable to add corroboration.
#
# **The first three used to be the whole list, and that was the defect.** This
# study's null -- layer removal never changes the verdict -- was obtained while
# the other three were absent because they need a sandbox report. §3.21 measured
# them over the archived cohort: `sigma_layer` fires on 43/43 and contributes a
# technique no other dynamic source found on 43/43, at weight 0.55, above every
# static layer this study did vary. A null taken without the second-heaviest
# contributor is a statement about an incomplete cascade, so the arm list now
# covers all six.
SOURCES: tuple[tuple[str, str], ...] = (
    ("yara_layer", "yara"),
    ("import_capability_layer", "static"),
    ("tool_artifact_layer", "yara"),
    ("sigma_layer", "sigma"),
    ("lolbin", "dynamic"),
    ("network_dga", "network"),
)

ARMS: tuple[str, ...] = ("all", *(f"no_{name}" for name, _ in SOURCES))


# ---------------------------------------------------------------------------
# Evidence construction (pure — unit-tested without an LLM)
# ---------------------------------------------------------------------------


def assign_to_sources(technique_ids: list[str], *, overlap: bool = False) -> dict[str, list[str]]:
    """Distribute the ground truth across the three sources.

    Two conditions, because they answer different questions and the first one
    alone answers the weaker of the two.

    **disjoint** (default) — round-robin, each technique claimed by exactly one
    source. Removing a source then simply removes its techniques, so the arms
    measure *does a lost technique reach the bundle*. Round-robin rather than a
    contiguous split so no source is systematically handed the easy techniques.
    **This condition produces zero corroborated techniques by construction**,
    which is what makes it too weak to speak to §1.10.

    **overlap** — each technique is claimed by **two** sources, alternating
    between two deliberately chosen pairs:

    * ``yara_layer`` + ``import_capability_layer`` — domains ``yara`` and
      ``static``, i.e. **two distinct domains → corroborated**.
    * ``yara_layer`` + ``tool_artifact_layer`` — **both emit on domain
      ``yara``**, so the cascade sees one domain and the technique is **not
      corroborated even though two independent detectors agreed**.

    That second pair is not a contrivance. It is what the production layers do,
    and it makes §1.10's structural finding *demonstrable* rather than inferred:
    corroboration is keyed to the domain tag, not to detector independence, so
    a second detector that happens to share a tag contributes nothing to the
    label the report surfaces most prominently.

    **One consequence of this design must be read as construction, not
    measurement.** ``yara_layer`` appears in *both* pairs, so removing it
    destroys **all** corroboration by arithmetic — the ``no_yara_layer`` arm is
    baked in and proves nothing on its own. That mirrors production, where
    §1.10 measured yara firing on 89.5% of samples against import-capability's
    52.6%, but it means the informative arms are the other two:

    * ``no_import_capability_layer`` — the techniques survive (yara still claims
      them) but **lose their corroboration**. This is the arm that tests whether
      corroboration loss alone reaches the verdict.
    * ``no_tool_artifact_layer`` — its techniques are also claimed by yara and it
      contributed **no** corroboration to begin with, so the prediction is
      **no change at all**. Falsifiable, and the sharpest test in the set.
    """
    out: dict[str, list[str]] = {name: [] for name, _ in SOURCES}
    names = [name for name, _ in SOURCES]
    if not overlap:
        for i, tid in enumerate(technique_ids):
            out[names[i % len(names)]].append(str(tid).upper())
        return out

    # Alternate the two pairs so both the cross-domain and the same-domain case
    # appear in every sample rather than splitting by sample.
    pairs = (
        ("yara_layer", "import_capability_layer"),  # distinct domains -> corroborated
        ("yara_layer", "tool_artifact_layer"),  # SAME domain -> not corroborated
    )
    for i, tid in enumerate(technique_ids):
        for name in pairs[i % len(pairs)]:
            out[name].append(str(tid).upper())
    return out


def sources_for_arm(arm: str) -> list[tuple[str, str]]:
    """The (source, domain) pairs active in ``arm``. Unknown arm → all sources."""
    if arm == "all" or not arm.startswith("no_"):
        return list(SOURCES)
    removed = arm[3:]
    return [(name, domain) for name, domain in SOURCES if name != removed]


def build_isr_reports(assignment: dict[str, list[str]], arm: str) -> dict[str, Any]:
    """Synthesise one ``AgentISR`` per active source. Deterministic, no LLM.

    Confidence is fixed at the layer's nominal trust so the arms differ only in
    which layers exist — a varying confidence would confound layer removal with
    a confidence change.
    """
    from maljan.schemas.isr_models import AgentISR, ClaimEvidence

    reports: dict[str, Any] = {}
    for name, domain in sources_for_arm(arm):
        tids = assignment.get(name, [])
        if not tids:
            continue
        reports[name] = AgentISR(
            agent_id=name,
            domain=domain,
            claims=[
                ClaimEvidence(
                    claim=f"{name} matched a deterministic pattern for {tid}",
                    evidence_ref=f"{name}: rule hit for {tid}",
                    confidence=0.9,
                    technique_id=tid,
                )
                for tid in tids
            ],
        )
    return reports


def bundle_technique_ids(bundle: Any) -> set[str]:
    """ATT&CK ids carried by a bundle's attack-pattern SDOs."""
    out: set[str] = set()
    for obj in getattr(bundle, "objects", []) or []:
        otype = getattr(obj, "type", None) or (obj.get("type") if isinstance(obj, dict) else None)
        if otype != "attack-pattern":
            continue
        refs = getattr(obj, "external_references", None)
        if refs is None and isinstance(obj, dict):
            refs = obj.get("external_references")
        for ref in refs or []:
            ext = getattr(ref, "external_id", None)
            if ext is None and isinstance(ref, dict):
                ext = ref.get("external_id")
            if isinstance(ext, str) and ext.upper().startswith("T"):
                out.add(ext.upper())
    return out


def jaccard(a: set[str], b: set[str]) -> float:
    """Overlap of two technique sets. Two empty sets are identical, not undefined."""
    if not a and not b:
        return 1.0
    union = a | b
    return len(a & b) / len(union) if union else 1.0


def verdict_changed(baseline: set[str], arm: set[str]) -> bool:
    """Did removing the layer change what the analyst receives at all?"""
    return baseline != arm


@dataclass
class ArmResult:
    sample_id: str
    arm: str
    repeat: int
    technique_ids: list[str]
    n_objects: int
    integrity_invocations: int
    integrity_objects_removed: int
    integrity_dropped: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def result_from_dict(d: dict[str, Any]) -> ArmResult:
    return ArmResult(
        sample_id=str(d["sample_id"]),
        arm=str(d["arm"]),
        repeat=int(d["repeat"]),
        technique_ids=[str(t) for t in d.get("technique_ids", [])],
        n_objects=int(d.get("n_objects", 0)),
        integrity_invocations=int(d.get("integrity_invocations", 0)),
        integrity_objects_removed=int(d.get("integrity_objects_removed", 0)),
        integrity_dropped=dict(d.get("integrity_dropped") or {}),
    )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def b3_block(results: list[ArmResult]) -> list[str]:
    """Per-arm change against the `all` baseline, paired by (sample, repeat)."""
    index = {(r.sample_id, r.arm, r.repeat): r for r in results}
    keys = sorted({(r.sample_id, r.repeat) for r in results if r.arm == "all"})
    lines = [
        "## B3 — does removing a layer change the verdict?",
        "",
        "| arm removed | verdict changed | mean Jaccard vs `all` | 95% CI | n |",
        "|---|---|---|---|---|",
    ]
    for arm in ARMS:
        if arm == "all":
            continue
        js: list[float] = []
        changed = 0
        for sid, rep in keys:
            base = index.get((sid, "all", rep))
            other = index.get((sid, arm, rep))
            if base is None or other is None:
                continue
            a, b = set(base.technique_ids), set(other.technique_ids)
            js.append(jaccard(a, b))
            changed += 1 if verdict_changed(a, b) else 0
        if not js:
            lines.append(f"| `{arm[3:]}` | — | — | — | 0 |")
            continue
        lo, hi = bootstrap_ci(js)
        lines.append(
            f"| `{arm[3:]}` | **{changed}/{len(js)}** | {mean(js):.3f} "
            f"| [{lo:.3f}, {hi:.3f}] | {len(js)} |"
        )
    lines.append("")
    return lines


def b4_block(results: list[ArmResult]) -> list[str]:
    """What the STIX integrity pass actually did across every generated bundle."""
    fired = [r for r in results if r.integrity_invocations > 0]
    removed_any = [r for r in fired if r.integrity_objects_removed > 0]
    totals: dict[str, int] = {}
    for r in results:
        for reason, count in r.integrity_dropped.items():
            totals[reason] = totals.get(reason, 0) + count
    lines = [
        "## B4 — what the STIX integrity pass does on fresh bundles",
        "",
        f"- bundles generated: **{len(results)}**",
        f"- integrity pass ran on: **{len(fired)}**",
        f"- pass **removed something** on: **{len(removed_any)}** "
        f"({(len(removed_any) / len(results) * 100 if results else 0):.1f}%)",
        f"- objects removed in total: **{sum(r.integrity_objects_removed for r in results)}**",
        "",
    ]
    if any(totals.values()):
        lines += ["| removal reason | count |", "|---|---|"]
        lines += [f"| {k} | {v} |" for k, v in sorted(totals.items()) if v]
        lines.append("")
    else:
        lines += [
            "**The pass fired and removed nothing.** That is a result for C7, not a null:",
            "it means the judge's bundles were already internally consistent on this evidence,",
            "so the repair stage recovered nothing that rejection would have discarded *here*.",
            "The claim that repairing beats rejecting needs a population where the defects",
            "actually occur — which is the CAPE-driven runs, not clean synthetic evidence.",
            "",
        ]
    return lines


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def _run_one(container: Any, judge: Any, isr_reports: dict[str, Any]) -> tuple[Any, dict]:
    """Cascade + judge over one evidence set. Returns (bundle, ledger snapshot)."""
    from maljan.analysis.ttp_cascade import TTPCascadeEngine

    ledger = TruncationLedger()
    judge.truncation_ledger = ledger

    summary = TTPCascadeEngine().compute(isr_reports)
    reports = {
        name: "\n".join(f"- {c.claim}" for c in isr.claims) for name, isr in isr_reports.items()
    }
    bundle = await judge.give_verdict(
        reports=reports,
        history=[],
        isr_reports=isr_reports,
        cascade_summary=summary,
    )
    return bundle, ledger.snapshot()


def main_async(repeats: int, smoke: bool, overlap: bool, checkpoint: Path) -> None:
    samples = load_samples()
    if smoke:
        samples = samples[:1]
        repeats = 1
    if not samples:
        print("No fixtures found — aborting.", flush=True)
        return

    results: list[ArmResult] = []
    done: set[str] = set()
    if checkpoint.exists():
        for line in checkpoint.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                done.add(rec["key"])
                results.append(result_from_dict(rec))
        print(f"Resume: {len(done)} generations in {checkpoint}.", flush=True)

    container = ServiceContainer(get_settings(), mock=False)
    judge = container.get_judge_agent()
    # The B1 lesson, applied to the judge path this time. Production gives the
    # verdict a 600 s wall clock and an 1800 s request timeout, both sized for a
    # real analysis; here a single degenerate decode would hold the batch for ten
    # minutes and there are 60 of them. 300 s is generous for an 8192-token
    # bundle at ~40 tok/s and cuts a runaway. See
    # ``eval_consensus_ablation.bind_eval_llm`` for why this must be a bound
    # per-request kwarg rather than an attribute assignment.
    bind_eval_llm(judge, timeout_s=300)
    print(
        f"{len(samples)} sample(s), arms={list(ARMS)}, repeats={repeats}, "
        f"condition={'overlap' if overlap else 'disjoint'}.",
        flush=True,
    )

    for sid, truth in samples:
        assignment = assign_to_sources(truth, overlap=overlap)
        for rep in range(repeats):
            for arm in ARMS:
                key = f"{arm}:{sid}:{rep}"
                if key in done:
                    continue
                isr_reports = build_isr_reports(assignment, arm)
                try:
                    bundle, snap = asyncio.run(_run_one(container, judge, isr_reports))
                except Exception as exc:  # noqa: BLE001 — one bad verdict must not kill the batch
                    print(f"  SKIP {key}: {type(exc).__name__}: {exc}", flush=True)
                    continue
                tids = sorted(bundle_technique_ids(bundle))
                dropped = snap.get("integrity_dropped")
                res = ArmResult(
                    sample_id=sid,
                    arm=arm,
                    repeat=rep,
                    technique_ids=tids,
                    n_objects=len(getattr(bundle, "objects", []) or []),
                    integrity_invocations=int(snap.get("integrity_invocations", 0)),
                    integrity_objects_removed=int(snap.get("integrity_objects_removed", 0)),
                    integrity_dropped=dict(dropped) if isinstance(dropped, dict) else {},
                )
                results.append(res)
                with checkpoint.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps({"key": key, **res.to_dict()}) + "\n")
                print(
                    f"  {key}: {len(tids)} techniques, {res.n_objects} objects, "
                    f"integrity removed {res.integrity_objects_removed}",
                    flush=True,
                )

    condition = "overlap" if overlap else "disjoint"
    lines = [
        "# B3 + B4 — layer removal at the verdict, and what the integrity pass does",
        "",
        f"**Condition: `{condition}`.** In `disjoint` each technique is claimed by exactly one",
        "source, so **nothing is ever corroborated** and the arms only measure whether a lost",
        "technique reaches the bundle. In `overlap` each technique is claimed by two sources —",
        "alternating `yara`+`import_capability` (**distinct domains → corroborated**) and",
        "`yara`+`tool_artifact` (**same domain → NOT corroborated even though two detectors**",
        "**agreed**), which is what makes §1.10's structural finding demonstrable, not inferred.",
        "",
        "**Read `no_yara_layer` as construction, not measurement.** yara appears in both pairs, so",
        "removing it destroys all corroboration by arithmetic. The informative arms are",
        "`no_import_capability_layer` (techniques survive via yara but **lose corroboration**) and",
        "`no_tool_artifact_layer` (**predicted: no change at all** — its techniques are also",
        "in yara and it contributed no corroboration to begin with).",
        "",
        "- Input ISRs are **synthesised deterministically** from the fixture ground truth, so the",
        "  only variable between arms is which Layer-0 source exists.",
        "- Each source carries an **equal share** by construction. In production the rates are",
        "  wildly uneven (§1.10: yara 89.5%, import-capability 52.6%, tool-artifact **2.4%**), so",
        "  this measures the *mechanism*, not the real-world impact of removing a layer.",
        "- `tool_artifact_layer` emits on **yara's** cascade domain, which is why §1.10 found it",
        "  unable to add corroboration.",
        "",
    ]
    lines += b3_block(results)
    lines += b4_block(results)

    report = "\n".join(lines)
    print("\n" + report, flush=True)
    try:
        _OUT_FILE.write_text(report + "\n", encoding="utf-8")
        _JSON_FILE.write_text(
            json.dumps([r.to_dict() for r in results], indent=2) + "\n", encoding="utf-8"
        )
        print(f"\nWrote {_OUT_FILE} and {_JSON_FILE}", flush=True)
    except OSError as exc:
        print(f"Could not write report: {exc}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="B3/B4 layer removal at the verdict.")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--smoke", action="store_true")
    ap.add_argument(
        "--overlap",
        action="store_true",
        help="Each technique claimed by TWO sources, so corroboration exists and layer "
        "removal can cost it. The disjoint default produces zero corroborated techniques.",
    )
    ap.add_argument("--checkpoint", type=Path, default=_DEFAULT_CHECKPOINT)
    args = ap.parse_args()
    main_async(args.repeats, args.smoke, args.overlap, args.checkpoint)


if __name__ == "__main__":
    main()
