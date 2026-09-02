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
four Layer-0 sources that fire on this corpus, ISRs are synthesised
**deterministically**, the cascade runs over them, and the judge produces a
bundle. Arms remove one source at a time. The only variable is which layer
exists.

  all · no_yara_layer · no_import_capability_layer · no_tool_artifact_layer ·
  no_sigma_layer

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

**Which is exactly why two sources are absent from the arm list.** The equal-share
construction is a legitimate way to probe a mechanism, but only for a mechanism
that engages at all. `lolbin` and `network_dga` produce a claim on **0 of 97**
archived reports while being fed a median of 8888 API calls and 48-68 domains
respectively (§3.23) — they are offered the evidence and decline it. Ablating
them under an equal share would describe a system that does not exist. They are
excluded by measurement, the measurement travels in the run's JSON, and the
firing rates are the finding rather than a footnote.

The fixtures are drawn from families carrying at least three techniques per
source, for a reason that cost a run: at fewer techniques than sources,
round-robin hands the last source **nothing**, its removal arm becomes identical
to `all`, and the arm reports a null it obtained by arithmetic. See
``load_large_fixtures``.

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
import os
import random
import subprocess
import sys
import time
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
    cluster_ci,
    mean,
)


def _artefact(overlap: bool, suffix: str) -> Path:
    """Output path named by condition: ``_overlap`` or ``_disjoint``.

    The two conditions used to write one unsuffixed file that was then copied
    by hand to the name paper_facts.py reads, which left a byte-identical
    duplicate in the tree and no record of which condition the unsuffixed one
    was. The name now says.
    """
    condition = "overlap" if overlap else "disjoint"
    return _REPO_ROOT / "tests" / "evaluation" / f"layer0_verdict_v2_{condition}{suffix}"


_DEFAULT_CHECKPOINT = Path("/tmp/layer0_verdict_v2_checkpoint.jsonl")

# The Layer-0 sources that **can** move a verdict on this corpus, with the
# cascade domain each actually emits on, taken from the production layers rather
# than assumed. tool_artifact sharing yara's domain is not an accident of this
# harness -- it is what the production layer does
# (src/maljan/analysis/tool_artifact_layer.py), and it is why §1.10 found that
# source unable to add corroboration.
#
# **This list was wrong twice, in opposite directions, and both errors are
# recorded because each one would have produced a publishable-looking null.**
#
# *Too small.* The first three were the whole list, and the study's null -- layer
# removal never changes the verdict -- was obtained while `sigma_layer` was
# absent because it needs a sandbox report. §3.21 measured it over the archived
# cohort: it fires on 43/43 and contributes a technique no other dynamic source
# found on 43/43, at weight 0.55, above every static layer that study varied. A
# null taken without the second-heaviest contributor describes an incomplete
# cascade.
#
# *Too large.* The repair added all three sandbox-fed sources, which was worse.
# Two of them produce nothing on this corpus, and §3.23 establishes that they
# are **fed and decline** rather than failing: over the 97 archived reports
# `lolbin` returns no claim on 97/97 against a median of 8888 recorded API calls
# and 2 processes, and `network_dga` returns no claim on 97/97 while the network
# extractor hands it 48-68 domains per sample, none of which score as generated.
# Re-measured after the §3.24 recovery more than doubled the cohort: the rate did
# not move off zero, and `sigma_layer` — the source that *is* kept — went from
# 43/43 to 94/97.
# Giving either an equal share of the ground truth would ablate a mechanism that
# never engages -- measuring a system that does not exist and reporting the
# result as if it described this one. They are therefore excluded from the arms
# **by measurement, with the measurement reported**, which is the firing-rate-
# before-effect discipline this project applies to every other claim.
#
# It also broke the harness's own precondition: six sources over five-technique
# fixtures assigns 1/1/1/1/1/**0**, so the last arm was byte-identical to `all`
# and its null was arithmetic. See ``load_large_fixtures`` for the size floor
# that now prevents this class of error rather than the one instance of it.
SOURCES: tuple[tuple[str, str], ...] = (
    ("yara_layer", "yara"),
    ("import_capability_layer", "static"),
    ("tool_artifact_layer", "yara"),
    ("sigma_layer", "sigma"),
)

# Sources measured and then excluded, kept here so the exclusion is legible in
# the artefact rather than only in this comment. Reported in the run's JSON.
EXCLUDED_SOURCES: tuple[tuple[str, str, str], ...] = (
    (
        "lolbin",
        "dynamic",
        "no claim on 97/97 archived reports (median 8888 API calls, 2 processes present)",
    ),
    (
        "network_dga",
        "network",
        "no claim on 97/97 archived reports (48-68 domains supplied per sample)",
    ),
)

ARMS: tuple[str, ...] = ("all", *(f"no_{name}" for name, _ in SOURCES))


# ---------------------------------------------------------------------------
# Evidence construction (pure — unit-tested without an LLM)
# ---------------------------------------------------------------------------


def assign_to_sources(technique_ids: list[str], *, overlap: bool = False) -> dict[str, list[str]]:
    """Distribute the ground truth across the four sources.

    Two conditions, because they answer different questions and the first one
    alone answers the weaker of the two.

    **disjoint** (default) — round-robin, each technique claimed by exactly one
    source. Removing a source then simply removes its techniques, so the arms
    measure *does a lost technique reach the bundle*. Round-robin rather than a
    contiguous split so no source is systematically handed the easy techniques.
    **This condition produces zero corroborated techniques by construction**,
    which is what makes it too weak to speak to §1.10.

    **overlap** — each technique is claimed by **two** sources, rotating through
    three deliberately chosen pairs:

    * ``yara_layer`` + ``import_capability_layer`` — domains ``yara`` and
      ``static``, i.e. **two distinct domains → corroborated**.
    * ``yara_layer`` + ``tool_artifact_layer`` — **both emit on domain
      ``yara``**, so the cascade sees one domain and the technique is **not
      corroborated even though two independent detectors agreed**.
    * ``sigma_layer`` + ``import_capability_layer`` — domains ``sigma`` and
      ``static``, **corroborated, and reachable without yara**.

    That second pair is not a contrivance. It is what the production layers do,
    and it makes §1.10's structural finding *demonstrable* rather than inferred:
    corroboration is keyed to the domain tag, not to detector independence, so
    a second detector that happens to share a tag contributes nothing to the
    label the report surfaces most prominently.

    **The third pair repairs a defect in this design, not just its size.** With
    only the first two, ``yara_layer`` appeared in *both*, so removing it
    destroyed **all** corroboration by arithmetic: ``no_yara_layer`` was baked in
    and proved nothing, and the earlier write-up said so. A yara-free
    corroborated pair means that arm now leaves the sigma+static corroborations
    standing, so its result is a measurement. Every arm in the set is now
    informative:

    * ``no_yara_layer`` — loses the yara-paired corroborations and the techniques
      only yara claimed, while sigma+static corroboration **survives**. Tests
      whether a partial loss of corroboration reaches the verdict.
    * ``no_import_capability_layer`` — the techniques survive (yara or sigma still
      claims them) but **lose their corroboration**, in both corroborated pairs.
      The arm that isolates corroboration loss from technique loss.
    * ``no_tool_artifact_layer`` — its techniques are also claimed by yara and it
      contributed **no** corroboration to begin with, so the prediction is
      **no change at all**. Falsifiable, and the sharpest test in the set.
    * ``no_sigma_layer`` — removes the heaviest-weighted source (0.55) and one of
      the two corroborated pairs, with yara's pair untouched. The mirror of
      ``no_yara_layer``, which is what makes the pair of them interpretable.
    """
    out: dict[str, list[str]] = {name: [] for name, _ in SOURCES}
    names = [name for name, _ in SOURCES]
    if not overlap:
        for i, tid in enumerate(technique_ids):
            out[names[i % len(names)]].append(str(tid).upper())
        return out

    # Rotate the three pairs so the cross-domain, same-domain and yara-free cases
    # all appear in every sample rather than splitting by sample.
    pairs = (
        ("yara_layer", "import_capability_layer"),  # distinct domains -> corroborated
        ("yara_layer", "tool_artifact_layer"),  # SAME domain -> not corroborated
        ("sigma_layer", "import_capability_layer"),  # corroborated without yara
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
        js_clusters: list[str] = []
        changed = 0
        for sid, rep in keys:
            base = index.get((sid, "all", rep))
            other = index.get((sid, arm, rep))
            if base is None or other is None:
                continue
            a, b = set(base.technique_ids), set(other.technique_ids)
            js.append(jaccard(a, b))
            js_clusters.append(sid)
            changed += 1 if verdict_changed(a, b) else 0
        if not js:
            lines.append(f"| `{arm[3:]}` | — | — | — | 0 |")
            continue
        lo, hi = cluster_ci(js, js_clusters)
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


GT_DIR = _REPO_ROOT / "tests" / "evaluation" / "ground_truth" / "attck_malware"
FIXTURE_SEED = 20260812
LLAMA_UNIT = "c3-llama"
LLAMA_BIN = os.environ.get(
    "LLAMA_BIN", "/home/user/maljan-llm-build/ik_llama.cpp/build-cuda/bin/llama-server"
)
LLAMA_MODEL = str(_REPO_ROOT / "models" / "Qwen3.6-35B-A3B-IQ3_K_R4.gguf")
GRACE = _REPO_ROOT / "logs" / "night-job.grace"


def load_large_fixtures(
    *, min_techniques: int = 12, n: int = 8, seed: int = FIXTURE_SEED
) -> list[tuple[str, list[str]]]:
    """Families carrying enough ground truth that every source gets a real share.

    **The size floor is a precondition, not a preference.** With ``len(SOURCES)``
    sources, round-robin over a fixture of *k* techniques gives the last source
    ``k // len(SOURCES)`` of them; at *k* < ``len(SOURCES)`` that is zero, the
    removal arm becomes byte-identical to ``all``, and the arm reports a null it
    obtained by arithmetic. That is exactly how the six-source run was invalid:
    the shared five-technique fixtures assign 1/1/1/1/1/**0**.

    A floor of 12 over four sources guarantees each source ≥3 claims, so removing
    one is a graded perturbation rather than an all-or-nothing one, and the
    overlap condition can produce several corroborated techniques per pair
    instead of one. The assertion below enforces the relationship rather than the
    number, so changing ``SOURCES`` cannot silently re-introduce the defect.

    Selection is a seeded sample over the families that clear the floor, recorded
    by name in the run's JSON so the set is re-derivable rather than curated.
    """
    floor = max(min_techniques, 3 * len(SOURCES))
    pool: list[tuple[str, list[str]]] = []
    for path in sorted(GT_DIR.glob("*.json")):
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        tids = sorted({str(t).upper() for t in (rec.get("technique_ids") or [])})
        if len(tids) >= floor:
            pool.append((path.stem, tids))
    if not pool:
        return []
    chosen = random.Random(seed).sample(pool, min(n, len(pool)))
    chosen.sort(key=lambda row: row[0])
    for sid, tids in chosen:
        assert len(tids) >= 3 * len(SOURCES), f"{sid}: {len(tids)} techniques under the floor"
    return chosen


def restart_llama() -> bool:
    """Fresh model server, in its own cgroup. Returns True when healthy.

    §3.22: the first attempt at this study did **not** do this, reached 17.8 GB
    of its 20 GB cap after a hundred verdicts, and died at 102/105 arms on judge
    connection errors that were really a suffocating server. The transient unit
    keeps the memory accounted where it belongs (§E5 §3) instead of to whatever
    launched the harness, and the grace marker tells the memory guard that this
    drop is declared rather than runaway.
    """
    import httpx

    GRACE.parent.mkdir(parents=True, exist_ok=True)
    # The epoch goes *inside* the marker, not just on its mtime: the guard
    # reads its age with a builtin rather than stat(1), because the pass that
    # needs this answer is the one where forking has stopped working.
    GRACE.write_text(f"{int(time.time())}\n")
    subprocess.run(["pkill", "-f", "llama-server"], capture_output=True)
    subprocess.run(
        ["systemctl", "--user", "reset-failed", f"{LLAMA_UNIT}.service"], capture_output=True
    )
    time.sleep(5)
    subprocess.Popen(
        [
            "systemd-run",
            "--user",
            f"--unit={LLAMA_UNIT}",
            "--collect",
            "--property=MemoryMax=20G",
            "--property=MemorySwapMax=2G",
            LLAMA_BIN,
            "-m",
            LLAMA_MODEL,
            "-c",
            "65536",
            "-t",
            "16",
            "-fa",
            "on",
            "-ctk",
            "q8_0",
            "-ctv",
            "q8_0",
            "-ngl",
            "999",
            "-ot",
            r"blk\.([1-3][0-9])\.ffn_(up|gate|down)_exps=CPU",
            "--context-shift",
            "on",
            "--jinja",
            "--alias",
            "qwen3.6-35b-a3b",
            "--host",
            "0.0.0.0",
            "--port",
            "8080",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(60):
        try:
            if httpx.get("http://localhost:8080/health", timeout=5).json().get("status") == "ok":
                GRACE.unlink(missing_ok=True)
                return True
        except Exception:  # noqa: BLE001 — still starting
            pass
        time.sleep(5)
    GRACE.unlink(missing_ok=True)
    return False


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
    samples = load_large_fixtures()
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
        print(f"  fixture {sid}: {len(truth)} techniques", flush=True)

    for sid, truth in samples:
        assignment = assign_to_sources(truth, overlap=overlap)
        for rep in range(repeats):
            for arm in ARMS:
                key = f"{arm}:{sid}:{rep}"
                if key in done:
                    continue
                # **A fresh server per arm, not per fixture.** The per-fixture
                # cadence was copied from a design whose fixtures carried five
                # techniques. These carry twelve to fifty-one, and on 2026-08-14
                # llama-server went from 12 GB to 19.9 GB — its whole 20 GB cap —
                # inside the first fixture's five arms, with the host down to
                # 4.0 GB and the memory guard about to intervene. That is §3.22's
                # failure repeating at a finer grain: the growth is per judge
                # call, so the restart has to be too. Forty model loads cost
                # about half an hour on a four-hour run.
                if not restart_llama():
                    print("  model server did not come back healthy — stopping", flush=True)
                    return
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
        "technique reaches the bundle. In `overlap` each technique is claimed by two sources,",
        "rotating `yara`+`import_capability` (**distinct domains → corroborated**),",
        "`yara`+`tool_artifact` (**same domain → NOT corroborated even though two detectors**",
        "**agreed**), and `sigma`+`import_capability` (**corroborated without yara**). The second",
        "pair is what makes §1.10's structural finding demonstrable, not inferred; the third is",
        "what makes `no_yara_layer` a measurement rather than an arithmetic certainty.",
        "",
        "**Every arm here is informative, which was not true of the earlier design.** With only",
        "the first two pairs, yara appeared in both, so removing it destroyed all corroboration by",
        "construction and that arm proved nothing. The yara-free pair leaves the sigma+static",
        "corroborations standing, so `no_yara_layer` and `no_sigma_layer` now mirror each other.",
        "`no_tool_artifact_layer` remains the sharpest test: **predicted no change at all**, since",
        "its techniques are also in yara and it contributed no corroboration to begin with.",
        "",
        "- Input ISRs are **synthesised deterministically** from the fixture ground truth, so the",
        "  only variable between arms is which Layer-0 source exists.",
        "- Each source carries an **equal share** by construction. In production the rates are",
        "  wildly uneven (§1.10: yara 89.5%, import-capability 52.6%, tool-artifact **2.4%**), so",
        "  this measures the *mechanism*, not the real-world impact of removing a layer.",
        "- `tool_artifact_layer` emits on **yara's** cascade domain, which is why §1.10 found it",
        "  unable to add corroboration.",
        "- **Two Layer-0 sources are excluded, by measurement rather than by choice.** Over the 43",
        "  archived reports `lolbin` and `network_dga` each produce a claim on **0/43** — while",
        "  being fed a median of 3356 API calls and 49-63 domains respectively (§3.23). Handing",
        "  either an equal share would ablate a mechanism that never engages in this deployment.",
        f"- Fixtures carry **≥{3 * len(SOURCES)} techniques** so every source holds ≥3 claims. The",
        "  five-technique fixtures used elsewhere assign the last of six sources **zero**, which",
        "  is how the six-source run produced a null it obtained by arithmetic.",
        "",
    ]
    lines += b3_block(results)
    lines += b4_block(results)

    report = "\n".join(lines)
    print("\n" + report, flush=True)
    try:
        _artefact(overlap, ".md").write_text(report + "\n", encoding="utf-8")
        # Provenance travels with the numbers: which sources were in, which were
        # measured out and why, which fixtures were drawn and under what seed.
        # The earlier artefact was a bare list of arms, and when the source list
        # changed underneath it there was nothing on disk that said so.
        _artefact(overlap, ".json").write_text(
            json.dumps(
                {
                    "schema": "layer0-verdict/v2",
                    "condition": condition,
                    "repeats": repeats,
                    "fixture_seed": FIXTURE_SEED,
                    "sources": [{"name": n, "domain": d} for n, d in SOURCES],
                    "excluded_sources": [
                        {"name": n, "domain": d, "reason": why} for n, d, why in EXCLUDED_SOURCES
                    ],
                    "fixtures": [{"sample_id": s, "n_techniques": len(t)} for s, t in samples],
                    "arms": [r.to_dict() for r in results],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nWrote {_artefact(overlap, '.md')} and {_artefact(overlap, '.json')}", flush=True)
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
