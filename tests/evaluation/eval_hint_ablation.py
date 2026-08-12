"""End-to-end ablation: does the section 7.1 schema-pruning hint improve the judge?

findings-log section 1.7 measured the *category classifier* in isolation and noted the
decisive question was deferred: since the hint is advisory, does injecting it
actually improve the judge's final STIX bundle? This harness answers that with a
real LLM-in-the-loop, paired A/B.

Design (mindful of section 3.4: an N=1 LLM measurement is not a valid instrument):
  * **Paired** — every sample is judged twice, ON (real hint) vs OFF (hint forced
    to ""), with everything else identical, so per-sample difficulty cancels.
  * **Forced/structured output** — give_verdict already uses
    with_structured_output(Bundle), removing truncation as a variable.
  * **N >> 1** — a stratified set of ATT&CK families provides the replication;
    we report the mean paired delta, a sign test, and a bootstrap CI, not a
    single number.

Ground truth: the cached ATT&CK bundle. Sample text = the malware family's
description (the same prose category_eval_data labels); GT techniques = that
family's `uses` relationships to attack-patterns. Both come from one source and
join on the ATT&CK software ID, so text and labels are consistent.

Metrics per condition: TTP precision/recall/F1 (exact and parent-collapsed),
hallucination rate (predicted technique absent from the 691-ID catalog), and
STIX shape (objects, attack-patterns, indicators, relationships, confidence-
annotated relationships).

Run:  uv run python tests/evaluation/eval_hint_ablation.py [--per-category N] [--smoke]
Requires a live llama-server (the judge LLM). Measurement tool, not a pytest test.
"""

# Bootstraps sys.path before first-party imports (E402 is intentional here).
# ruff: noqa: E402

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

_OUTPUT_DIR = Path(__file__).resolve().parent

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from maljan.agents.judge_agent import JudgeAgent
from maljan.analysis.schema_pruner import MalwareCategory
from maljan.core.config import get_settings
from maljan.core.container import ServiceContainer
from tests.evaluation.category_eval_data import (
    CategorySample,
    build_category_samples,
)

_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_CATS = [
    MalwareCategory.RANSOMWARE,
    MalwareCategory.RAT,
    MalwareCategory.DROPPER,
    MalwareCategory.WORM,
    MalwareCategory.INFOSTEALER,
]


# ---------------------------------------------------------------------------
# Ground-truth technique extraction (malware --uses--> attack-pattern)
# ---------------------------------------------------------------------------
def _build_gt_techniques(bundle_path: Path) -> dict[str, set[str]]:
    """Map ATT&CK software ID (S####) -> set of technique IDs it `uses`."""
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    ap_stixid_to_tid: dict[str, str] = {}
    mal_stixid_to_sid: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        otype = obj.get("type")
        if otype == "attack-pattern":
            tid = _attck_external_id(obj)
            if tid:
                ap_stixid_to_tid[obj["id"]] = tid.upper()
        elif otype == "malware":
            sid = _attck_external_id(obj)
            if sid:
                mal_stixid_to_sid[obj["id"]] = sid.upper()

    gt: dict[str, set[str]] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        src = obj.get("source_ref", "")
        tgt = obj.get("target_ref", "")
        sid = mal_stixid_to_sid.get(src)
        tid = ap_stixid_to_tid.get(tgt)
        if sid and tid:
            gt.setdefault(sid, set()).add(tid)
    return gt


def _attck_external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            ext = ref.get("external_id")
            if isinstance(ext, str) and ext:
                return ext
    return None


# ---------------------------------------------------------------------------
# Bundle inspection (robust to stix2 objects or plain dicts)
# ---------------------------------------------------------------------------
def _get(obj: object, key: str) -> object:
    if isinstance(obj, dict):
        return obj.get(key)
    try:
        return obj[key]  # type: ignore[index]
    except Exception:  # noqa: BLE001
        return getattr(obj, key, None)


def _iter_external_ids(obj: object) -> list[str]:
    refs = _get(obj, "external_references") or []
    out: list[str] = []
    if isinstance(refs, list):
        for r in refs:
            ext = _get(r, "external_id")
            if isinstance(ext, str) and _TID_RE.match(ext):
                out.append(ext.upper())
    return out


@dataclass
class BundleStats:
    techniques: set[str] = field(default_factory=set)
    n_objects: int = 0
    n_attack_patterns: int = 0
    n_indicators: int = 0
    n_relationships: int = 0
    n_conf_relationships: int = 0  # relationships carrying x_maljan_confidence


def _inspect_bundle(bundle: object) -> BundleStats:
    objs = _get(bundle, "objects") or []
    st = BundleStats()
    if not isinstance(objs, list):
        return st
    st.n_objects = len(objs)
    for o in objs:
        otype = _get(o, "type")
        if otype == "attack-pattern":
            st.n_attack_patterns += 1
            for tid in _iter_external_ids(o):
                st.techniques.add(tid)
        elif otype == "indicator":
            st.n_indicators += 1
        elif otype == "relationship":
            st.n_relationships += 1
            if _get(o, "x_maljan_confidence") is not None:
                st.n_conf_relationships += 1
    return st


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def _parent(tid: str) -> str:
    return tid.split(".", 1)[0]


def _prf(pred: set[str], gold: set[str]) -> tuple[float, float, float]:
    if not pred and not gold:
        return 1.0, 1.0, 1.0
    tp = len(pred & gold)
    prec = tp / len(pred) if pred else 0.0
    rec = tp / len(gold) if gold else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return prec, rec, f1


@dataclass
class SampleScore:
    sample_id: str
    name: str
    category: str
    gt_n: int
    f1_exact: float
    f1_parent: float
    precision: float
    recall: float
    hallucinated: int
    stats: BundleStats
    hint_present: bool = False  # did the ON condition actually inject a hint?


# ---------------------------------------------------------------------------
# Checkpoint (JSONL) — makes the run pause/resume-able and crash-safe.
# Each completed sample appends one record {sample_id, on, off}; on restart we
# skip sample_ids already present. Decoding is deterministic (temp=0), so a
# resumed run reproduces the exact same results as an uninterrupted one.
# ---------------------------------------------------------------------------
def _stats_to_dict(st: BundleStats) -> dict:
    return {
        "techniques": sorted(st.techniques),
        "n_objects": st.n_objects,
        "n_attack_patterns": st.n_attack_patterns,
        "n_indicators": st.n_indicators,
        "n_relationships": st.n_relationships,
        "n_conf_relationships": st.n_conf_relationships,
    }


def _stats_from_dict(d: dict) -> BundleStats:
    return BundleStats(
        techniques=set(d.get("techniques", [])),
        n_objects=d.get("n_objects", 0),
        n_attack_patterns=d.get("n_attack_patterns", 0),
        n_indicators=d.get("n_indicators", 0),
        n_relationships=d.get("n_relationships", 0),
        n_conf_relationships=d.get("n_conf_relationships", 0),
    )


def _score_to_dict(s: SampleScore) -> dict:
    return {
        "sample_id": s.sample_id,
        "name": s.name,
        "category": s.category,
        "gt_n": s.gt_n,
        "f1_exact": s.f1_exact,
        "f1_parent": s.f1_parent,
        "precision": s.precision,
        "recall": s.recall,
        "hallucinated": s.hallucinated,
        "stats": _stats_to_dict(s.stats),
        "hint_present": s.hint_present,
    }


def _score_from_dict(d: dict) -> SampleScore:
    return SampleScore(
        sample_id=d["sample_id"],
        name=d["name"],
        category=d["category"],
        gt_n=d["gt_n"],
        f1_exact=d["f1_exact"],
        f1_parent=d["f1_parent"],
        precision=d["precision"],
        recall=d["recall"],
        hallucinated=d["hallucinated"],
        stats=_stats_from_dict(d["stats"]),
        hint_present=d.get("hint_present", False),
    )


def _score(
    pred: BundleStats, gold: set[str], valid_ids: set[str]
) -> tuple[float, float, float, float, int]:
    prec, rec, f1 = _prf(pred.techniques, gold)
    f1_parent = _prf({_parent(t) for t in pred.techniques}, {_parent(t) for t in gold})[2]
    hallucinated = len([t for t in pred.techniques if t not in valid_ids])
    return f1, f1_parent, prec, rec, hallucinated


# ---------------------------------------------------------------------------
# Sample selection
# ---------------------------------------------------------------------------
def _select(
    samples: list[CategorySample], gt: dict[str, set[str]], per_category: int
) -> list[tuple[CategorySample, set[str]]]:
    """Deterministic stratified pick: first `per_category` per category that have GT."""
    by_cat: dict[MalwareCategory, list[tuple[CategorySample, set[str]]]] = {c: [] for c in _CATS}
    for s in samples:
        techs = gt.get(s.sample_id.upper())
        if techs and s.category in by_cat:
            by_cat[s.category].append((s, techs))
    chosen: list[tuple[CategorySample, set[str]]] = []
    for c in _CATS:
        chosen.extend(by_cat[c][:per_category])
    return chosen


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
async def _run_one(
    judge_on: JudgeAgent, judge_off: JudgeAgent, text: str
) -> tuple[BundleStats | None, BundleStats | None]:
    reports = {"static": text}
    on = off = None
    try:
        b_on = await judge_on.give_verdict(reports, history=[])
        on = _inspect_bundle(b_on)
    except Exception as exc:  # noqa: BLE001
        print(f"    ON failed: {exc!r}", flush=True)
    try:
        b_off = await judge_off.give_verdict(reports, history=[])
        off = _inspect_bundle(b_off)
    except Exception as exc:  # noqa: BLE001
        print(f"    OFF failed: {exc!r}", flush=True)
    return on, off


def _mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def _bootstrap_ci(deltas: list[float], iters: int = 2000) -> tuple[float, float]:
    """Percentile bootstrap 95% CI for the mean of paired deltas.

    Deterministic: a fixed LCG provides resampling indices (Math.random is
    unavailable / non-reproducible; this keeps the CI stable across runs).
    """
    n = len(deltas)
    if n < 2:
        return (0.0, 0.0)
    means: list[float] = []
    seed = 0x9E3779B9
    for _ in range(iters):
        acc = 0.0
        for _ in range(n):
            seed = (1103515245 * seed + 12345) & 0x7FFFFFFF
            acc += deltas[seed % n]
        means.append(acc / n)
    means.sort()
    lo = means[int(0.025 * iters)]
    hi = means[int(0.975 * iters)]
    return (lo, hi)


async def main_async(per_category: int, smoke: bool, checkpoint: Path) -> None:
    from maljan.memory.attck_loader import ATTCK_CACHE_FILE

    if not ATTCK_CACHE_FILE.exists():
        print("ATT&CK cache missing — aborting.", flush=True)
        return

    valid_ids_path = _REPO_ROOT / "data" / "attck_valid_ids.json"
    valid_ids: set[str] = set()
    if valid_ids_path.exists():
        valid_ids = {t.upper() for t in json.loads(valid_ids_path.read_text())["technique_ids"]}

    samples = build_category_samples()
    gt = _build_gt_techniques(ATTCK_CACHE_FILE)
    chosen = _select(samples, gt, per_category if not smoke else 1)
    if smoke:
        chosen = chosen[:1]
    print(
        f"Selected {len(chosen)} samples (per_category={per_category}, smoke={smoke}).", flush=True
    )

    # Resume: seed scores from the checkpoint and skip sample_ids already done.
    on_scores: list[SampleScore] = []
    off_scores: list[SampleScore] = []
    done_ids: set[str] = set()
    if checkpoint.exists():
        for line in checkpoint.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            done_ids.add(rec["sample_id"])
            if rec.get("on"):
                on_scores.append(_score_from_dict(rec["on"]))
            if rec.get("off"):
                off_scores.append(_score_from_dict(rec["off"]))
        print(f"Resume: {len(done_ids)} samples already in checkpoint {checkpoint}.", flush=True)

    container = ServiceContainer(get_settings(), mock=False)
    llm = container.get_judge_llm()
    judge_on = JudgeAgent(llm=llm, category_backend="keyword")  # real hint
    judge_off = JudgeAgent(llm=llm, category_backend="keyword")
    judge_off._build_schema_hint = lambda *a, **k: ""  # type: ignore[method-assign]

    def _mk(
        stats: BundleStats | None, gold: set[str], s: CategorySample, hp: bool
    ) -> SampleScore | None:
        if stats is None:
            return None
        f1, f1p, prec, rec, hall = _score(stats, gold, valid_ids)
        return SampleScore(
            s.sample_id, s.name, s.category.value, len(gold), f1, f1p, prec, rec, hall, stats, hp
        )

    for i, (s, gold) in enumerate(chosen, 1):
        if s.sample_id in done_ids:
            print(f"[{i}/{len(chosen)}] {s.name} — already in checkpoint, skipping.", flush=True)
            continue
        # Whether the ON condition actually injects a hint (keyword may abstain
        # -> empty hint -> ON==OFF trivially; such pairs do not test the hint).
        hint_present = bool(judge_on._build_schema_hint({"static": s.full_text}, None))
        print(
            f"[{i}/{len(chosen)}] {s.name} ({s.category.value}, GT={len(gold)}, "
            f"hint={'yes' if hint_present else 'NO'})",
            flush=True,
        )
        on, off = await _run_one(judge_on, judge_off, s.full_text)
        on_sc = _mk(on, gold, s, hint_present)
        off_sc = _mk(off, gold, s, hint_present)
        for cond, sc in (("ON", on_sc), ("OFF", off_sc)):
            if sc is None:
                continue
            (on_scores if cond == "ON" else off_scores).append(sc)
            st = sc.stats
            print(
                f"    {cond}: F1={sc.f1_exact:.3f} (parent {sc.f1_parent:.3f}) "
                f"P={sc.precision:.3f} R={sc.recall:.3f} hall={sc.hallucinated} | "
                f"obj={st.n_objects} ap={st.n_attack_patterns} ind={st.n_indicators} "
                f"rel={st.n_relationships}",
                flush=True,
            )
        # Append this sample to the checkpoint immediately (crash/pause-safe).
        with checkpoint.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {
                        "sample_id": s.sample_id,
                        "on": _score_to_dict(on_sc) if on_sc else None,
                        "off": _score_to_dict(off_sc) if off_sc else None,
                    }
                )
                + "\n"
            )

    _report(on_scores, off_scores, chosen, per_category, smoke)


def _report(
    on: list[SampleScore],
    off: list[SampleScore],
    chosen: list[tuple[CategorySample, set[str]]],
    per_category: int,
    smoke: bool,
) -> None:
    # Pair by sample_id (only samples where BOTH conditions produced a bundle).
    on_by = {s.sample_id: s for s in on}
    off_by = {s.sample_id: s for s in off}
    all_paired = [sid for sid in on_by if sid in off_by]
    # The hint test only counts pairs where the ON condition actually had a hint
    # (keyword may abstain -> empty hint -> ON==OFF trivially, not a real test).
    paired_ids = [sid for sid in all_paired if on_by[sid].hint_present]
    deltas = [on_by[sid].f1_exact - off_by[sid].f1_exact for sid in paired_ids]
    deltas_p = [on_by[sid].f1_parent - off_by[sid].f1_parent for sid in paired_ids]
    wins = sum(1 for d in deltas if d > 1e-9)
    losses = sum(1 for d in deltas if d < -1e-9)
    ties = len(deltas) - wins - losses
    ci = _bootstrap_ci(deltas)

    # Aggregates are computed over the hint-present subset (the real comparison).
    on_hp = [on_by[sid] for sid in paired_ids]
    off_hp = [off_by[sid] for sid in paired_ids]

    def agg(xs: list[SampleScore], attr: str) -> float:
        return _mean([getattr(x, attr) for x in xs])

    def agg_stat(xs: list[SampleScore], attr: str) -> float:
        return _mean([float(getattr(x.stats, attr)) for x in xs])

    lines = [
        "# Schema-pruning hint ablation (LLM-in-the-loop, paired ON vs OFF)",
        "",
        f"- Samples judged twice (real hint vs forced-empty hint). {len(all_paired)} families "
        f"produced a bundle in both conditions; **{len(paired_ids)}** of them actually had a "
        f"hint (keyword non-UNKNOWN) and form the test set. per_category={per_category}, "
        f"smoke={smoke}.",
        "- GT techniques from ATT&CK `uses` relationships; text = family description.",
        "- Judge decoding is deterministic, so any ON-vs-OFF difference is attributable to the "
        "hint (no sampling noise) — the replication is across families.",
        "",
        "## Aggregate (mean over hint-present samples)",
        "",
        "| metric | ON (hint) | OFF (no hint) | delta |",
        "|---|---|---|---|",
    ]
    for label, attr in (
        ("TTP F1 (exact)", "f1_exact"),
        ("TTP F1 (parent)", "f1_parent"),
        ("precision", "precision"),
        ("recall", "recall"),
        ("hallucinated techniques", "hallucinated"),
    ):
        a, b = agg(on_hp, attr), agg(off_hp, attr)
        lines.append(f"| {label} | {a:.3f} | {b:.3f} | {a - b:+.3f} |")
    for label, attr in (
        ("objects", "n_objects"),
        ("attack-patterns", "n_attack_patterns"),
        ("indicators", "n_indicators"),
        ("relationships", "n_relationships"),
        ("conf-annotated rels", "n_conf_relationships"),
    ):
        a, b = agg_stat(on_hp, attr), agg_stat(off_hp, attr)
        lines.append(f"| {label} | {a:.2f} | {b:.2f} | {a - b:+.2f} |")

    lines += [
        "",
        "## Paired test (TTP F1 exact)",
        "",
        f"- mean delta (ON - OFF) = **{_mean(deltas):+.3f}**, 95% bootstrap CI "
        f"[{ci[0]:+.3f}, {ci[1]:+.3f}] over n={len(deltas)} pairs.",
        f"- parent-level mean delta = {_mean(deltas_p):+.3f}.",
        f"- sign test: ON wins {wins}, OFF wins {losses}, ties {ties}.",
        "- CI crossing 0 -> the hint's end-to-end effect is not distinguishable from "
        "noise at this N (consistent with section 1.7: an advisory, truncated hint has a "
        "bounded effect on the final bundle).",
        "",
        "## Per-sample (ON F1 / OFF F1, exact)",
        "",
        "| family | category | hint | GT | ON F1 | OFF F1 | delta |",
        "|---|---|---|---|---|---|---|",
    ]
    for sid in all_paired:
        o, f = on_by[sid], off_by[sid]
        lines.append(
            f"| {o.name} | {o.category} | {'yes' if o.hint_present else 'no'} | {o.gt_n} | "
            f"{o.f1_exact:.3f} | {f.f1_exact:.3f} | {o.f1_exact - f.f1_exact:+.3f} |"
        )

    report = "\n".join(lines)
    print("\n" + report, flush=True)
    out = _OUTPUT_DIR / "hint_ablation.md"
    try:
        out.write_text(report + "\n", encoding="utf-8")
        print(f"\nWrote {out}", flush=True)
    except OSError:
        pass


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-category", type=int, default=5, help="samples per category")
    ap.add_argument("--smoke", action="store_true", help="single-sample end-to-end check")
    ap.add_argument(
        "--checkpoint",
        type=str,
        default=str(_OUTPUT_DIR / "hint_ablation_checkpoint.jsonl"),
        help="JSONL checkpoint; completed samples are skipped on resume",
    )
    args = ap.parse_args()
    asyncio.run(main_async(args.per_category, args.smoke, Path(args.checkpoint)))


if __name__ == "__main__":
    main()
