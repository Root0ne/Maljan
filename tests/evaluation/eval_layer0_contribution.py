"""What each deterministic Layer-0 source actually contributes, and whether the
cascade's constants are load-bearing.

Two questions the paper cannot answer today.

**Which layers carry the corroboration signal?** The cascade rewards a technique seen
in several independent layers, but nobody has measured what each layer supplies on its
own: how many techniques, how much of that is unique to it, and how much is duplicated
by a cheaper source. A layer that never contributes a technique no other layer found is
paying for its place with nothing.

**Are the weights load-bearing or decorative?** ``LAYER_WEIGHTS`` runs 0.90 (yara) down
to 0.20 (network) and the cross-layer multipliers run 1.00 to 1.90. Those eleven
constants were chosen by judgement, never derived and never tested. Weighting evidence
by source reliability and rewarding agreement between independent sources is
Dempster-Shafer theory, which is decades old and has a principled treatment of exactly
this — including discounting sources that are *not* independent. So "our constants are
plausible" is not a defence; the question is whether the conclusions survive perturbing
them, and if they do not, which conclusions are actually artifacts of the numbers.

SCOPE, stated because it limits every number below: **three of six Layer-0 sources.**
``yara_layer``, ``import_capability_layer`` and ``tool_artifact_layer`` read the sample
bytes and its parsed PE, so they run offline. ``sigma_layer``, ``lolbin_layer`` and
``network_dga`` consume a sandbox report and cannot run without CAPE. This is a *static*
Layer-0 study and must be named that way; the three dynamic sources are exactly the ones
the cascade weights *below* yara, so their absence flatters nothing.

Deterministic throughout: no LLM, no sandbox, no network. Reproducible from the vendored
rule/catalog data plus a directory of samples.

Run:
    uv run python tests/evaluation/eval_layer0_contribution.py \
        --samples-dir data/samples --out tests/evaluation/layer0_contribution.json
"""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from maljan.analysis.import_capability_layer import build_import_capability_isr
from maljan.analysis.tool_artifact_layer import build_tool_artifact_isr
from maljan.analysis.ttp_cascade import CROSS_LAYER_MULTIPLIERS, LAYER_WEIGHTS, TTPCascadeEngine
from maljan.analysis.yara_layer import YaraLayer

# The three sources that need no sandbox. Keyed by the agent_id their ISR carries,
# so the cascade sees exactly what production would hand it.
_STATIC_SOURCES = ("yara_layer", "import_capability", "tool_artifact")


# ---------------------------------------------------------------------------
# Per-sample evidence collection
# ---------------------------------------------------------------------------


def collect_isrs(
    sample_path: Path, yara_layer: YaraLayer | None, tool_catalog: str
) -> dict[str, Any]:
    """Run the three offline Layer-0 sources over one sample.

    Returns ``{agent_id: AgentISR}``, the same shape ``TTPCascadeEngine.compute``
    takes in production. A source that finds nothing is simply absent, which is
    also what production does.
    """
    from maljan.extractors.pe_extractor import build_static_analysis

    isrs: dict[str, Any] = {}
    blob = sample_path.read_bytes()

    if yara_layer is not None:
        matches = yara_layer.scan(blob)
        if matches:
            isr = yara_layer.to_isr(matches)
            if isr is not None and isr.claims:
                isrs["yara_layer"] = isr

    try:
        static = build_static_analysis(sample_path=str(sample_path))
    except Exception:  # noqa: BLE001 - unparseable members are skipped, not fatal
        static = None
    if static is not None:
        cap_isr = build_import_capability_isr(static)
        if cap_isr is not None and cap_isr.claims:
            isrs["import_capability"] = cap_isr

    tool_isr, _matches = build_tool_artifact_isr(blob, tool_catalog)
    if tool_isr is not None and tool_isr.claims:
        isrs["tool_artifact"] = tool_isr

    return isrs


def _claim_techniques(isr: Any) -> set[str]:
    """Technique ids on an ISR's claims, normalised.

    The blank check is not decorative: a whitespace-only ``technique_id`` is truthy
    and survives a naive `!= "NONE"` filter, entering the sets as an empty-string
    "technique" that then appears to be corroborated across every source that also
    had one. Caught by ``test_claims_without_a_technique_id_are_ignored``.
    """
    out: set[str] = set()
    for claim in isr.claims:
        raw = getattr(claim, "technique_id", None)
        if raw is None:
            continue
        tid = str(raw).strip().upper()
        if tid and tid != "NONE":
            out.add(tid)
    return out


def techniques_by_source(isrs: dict[str, Any]) -> dict[str, set[str]]:
    """``{agent_id: {technique_id}}`` for one sample — the *source* view."""
    out: dict[str, set[str]] = {}
    for agent_id, isr in isrs.items():
        tids = _claim_techniques(isr)
        if tids:
            out[agent_id] = tids
    return out


def techniques_by_domain(isrs: dict[str, Any]) -> dict[str, set[str]]:
    """``{domain: {technique_id}}`` — the view the **cascade** actually sees.

    Not the same partition as ``techniques_by_source`` and the difference matters:
    ``tool_artifact`` emits ``domain="yara"``, so a technique found by both it and
    ``yara_layer`` counts as **one** contributing layer, not two. That is deliberate
    (both are rule-based Layer-0 and are not independent evidence), but it means
    source-level contribution overstates how much corroboration the cascade can see.
    Reporting only the source view would have made three sources look like three
    layers.
    """
    out: dict[str, set[str]] = {}
    for isr in isrs.values():
        domain = str(getattr(isr, "domain", "") or "unknown")
        tids = _claim_techniques(isr)
        if tids:
            out.setdefault(domain, set()).update(tids)
    return out


# ---------------------------------------------------------------------------
# Contribution analysis (pure — unit-tested)
# ---------------------------------------------------------------------------


def unique_contribution(per_source: dict[str, set[str]]) -> dict[str, set[str]]:
    """Techniques a source supplied that **no other source** did, for one sample.

    This is the leave-one-out question stated positively: drop this source and
    these techniques disappear from the run entirely.
    """
    out: dict[str, set[str]] = {}
    for src, tids in per_source.items():
        others: set[str] = set()
        for other, other_tids in per_source.items():
            if other != src:
                others |= other_tids
        out[src] = tids - others
    return out


def corroboration_histogram(per_source: dict[str, set[str]]) -> Counter[int]:
    """How many techniques were seen by exactly 1, 2, 3 … sources."""
    seen: Counter[str] = Counter()
    for tids in per_source.values():
        for tid in tids:
            seen[tid] += 1
    return Counter(seen.values())


def pairwise_overlap(per_source: dict[str, set[str]]) -> dict[str, int]:
    """Jaccard-free raw intersection sizes for each unordered source pair."""
    out: dict[str, int] = {}
    names = sorted(per_source)
    for i, a in enumerate(names):
        for b in names[i + 1 :]:
            out[f"{a}|{b}"] = len(per_source[a] & per_source[b])
    return out


# ---------------------------------------------------------------------------
# Cascade weight sensitivity
# ---------------------------------------------------------------------------


def _summary_signature(summary: Any, top_n: int) -> tuple[tuple[str, ...], frozenset[str]]:
    """What a downstream consumer actually reads: the top-N ranking and the
    corroborated set. If neither moves, the weight change was decorative."""
    ranked = tuple(r.technique_id for r in summary.top_techniques(top_n))
    corroborated = frozenset(r.technique_id for r in summary.results if r.is_corroborated)
    return ranked, corroborated


def weight_sensitivity(
    all_isrs: list[dict[str, Any]],
    perturbations: dict[str, dict[str, float]],
    top_n: int = 10,
) -> dict[str, Any]:
    """Re-run the cascade under perturbed weights and report what changed.

    ``perturbations`` maps a label to a full ``layer_weights`` mapping. The
    baseline is the shipped ``LAYER_WEIGHTS``.
    """
    engine = TTPCascadeEngine()

    baselines = [engine.compute(isrs) for isrs in all_isrs]
    base_sigs = [_summary_signature(s, top_n) for s in baselines]

    results: dict[str, Any] = {}
    for label, weights in perturbations.items():
        rank_changed = 0
        corr_changed = 0
        corr_delta = 0
        for isrs, (base_rank, base_corr) in zip(all_isrs, base_sigs, strict=True):
            summary = engine.compute(isrs, layer_weights=weights)
            rank, corr = _summary_signature(summary, top_n)
            if rank != base_rank:
                rank_changed += 1
            if corr != base_corr:
                corr_changed += 1
            corr_delta += len(corr) - len(base_corr)
        n = len(all_isrs)
        results[label] = {
            "weights": weights,
            "samples_with_changed_top_n": rank_changed,
            "samples_with_changed_corroborated_set": corr_changed,
            "fraction_top_n_changed": round(rank_changed / n, 4) if n else 0.0,
            "fraction_corroborated_changed": round(corr_changed / n, 4) if n else 0.0,
            "net_corroborated_delta": corr_delta,
        }
    return results


def build_perturbations() -> dict[str, dict[str, float]]:
    """Perturbations chosen to test *claims*, not to sweep a grid.

    Each one asks a question a reviewer would ask about the constants.
    """
    base = dict(LAYER_WEIGHTS)
    flat = dict.fromkeys(base, 0.5)

    inverted = dict(base)
    # Does the *ordering* matter, or only that the weights differ? Swap the most
    # and least trusted layers.
    inverted["yara"], inverted["network"] = base["network"], base["yara"]

    compressed = {k: 0.5 + (v - 0.5) * 0.25 for k, v in base.items()}
    stretched = {k: max(0.01, min(1.0, 0.5 + (v - 0.5) * 1.75)) for k, v in base.items()}

    yara_demoted = dict(base)
    # YARA carries the highest weight on a 30-rule corpus — the thinnest evidence
    # base in the system. What happens if it is merely average?
    yara_demoted["yara"] = 0.45

    return {
        "flat_0.5_all_layers": flat,
        "inverted_yara_network": inverted,
        "compressed_toward_0.5_x0.25": compressed,
        "stretched_from_0.5_x1.75": stretched,
        "yara_demoted_0.90_to_0.45": yara_demoted,
    }


# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description="Static Layer-0 contribution + cascade sensitivity.")
    ap.add_argument("--samples-dir", type=str, default="data/samples")
    ap.add_argument("--yara-rules", type=str, default="data/yara_ttp_rules.yaml")
    ap.add_argument("--tool-catalog", type=str, default="data/tool_artifacts_v1.json")
    ap.add_argument("--max-samples", type=int, default=0, help="0 = all")
    ap.add_argument("--top-n", type=int, default=10)
    ap.add_argument("--out", type=str, default="tests/evaluation/layer0_contribution.json")
    args = ap.parse_args()

    samples_dir = Path(args.samples_dir)
    if not samples_dir.is_dir():
        print(f"ERROR: --samples-dir not found: {samples_dir}", file=sys.stderr)
        return 2

    try:
        yara_layer = YaraLayer.from_yaml(args.yara_rules)
    except Exception as exc:  # noqa: BLE001
        print(f"WARN: YARA layer unavailable ({exc}); continuing without it.", file=sys.stderr)
        yara_layer = None

    files = sorted(
        p
        for p in samples_dir.iterdir()
        if p.is_file() and p.suffix.lower() in {".exe", ".dll", ".sys", ".scr"}
    )
    if args.max_samples:
        files = files[: args.max_samples]
    print(f"samples: {len(files)}", flush=True)

    all_isrs: list[dict[str, Any]] = []
    per_sample_sources: list[dict[str, set[str]]] = []
    fired = Counter()
    yielded: Counter[str] = Counter()
    unique_total: Counter[str] = Counter()
    overlap_total: Counter[str] = Counter()
    corr_hist: Counter[int] = Counter()
    domain_corr_hist: Counter[int] = Counter()
    domain_yield: Counter[str] = Counter()
    parsed = 0

    for i, path in enumerate(files, 1):
        if i % 25 == 0:
            print(f"  {i}/{len(files)}", flush=True)
        try:
            isrs = collect_isrs(path, yara_layer, args.tool_catalog)
        except Exception as exc:  # noqa: BLE001 - one bad sample must not end the run
            print(f"  skip {path.name}: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        parsed += 1
        if not isrs:
            continue
        all_isrs.append(isrs)
        per_source = techniques_by_source(isrs)
        per_sample_sources.append(per_source)

        for src, tids in per_source.items():
            fired[src] += 1
            yielded[src] += len(tids)
        for src, tids in unique_contribution(per_source).items():
            unique_total[src] += len(tids)
        overlap_total.update(pairwise_overlap(per_source))
        corr_hist.update(corroboration_histogram(per_source))

        per_domain = techniques_by_domain(isrs)
        domain_corr_hist.update(corroboration_histogram(per_domain))
        for domain, tids in per_domain.items():
            domain_yield[domain] += len(tids)

    n = len(per_sample_sources)
    print(f"parsed {parsed}, produced Layer-0 evidence on {n}", flush=True)

    contribution = {}
    for src in _STATIC_SOURCES:
        f = fired[src]
        contribution[src] = {
            "samples_fired": f,
            "fire_rate": round(f / parsed, 4) if parsed else 0.0,
            "techniques_emitted_total": yielded[src],
            "techniques_per_firing_sample": round(yielded[src] / f, 2) if f else 0.0,
            "unique_to_this_source_total": unique_total[src],
            "unique_share": round(unique_total[src] / yielded[src], 4) if yielded[src] else 0.0,
        }

    result: dict[str, Any] = {
        "schema": "maljan-layer0-contribution/v1",
        "scope": (
            "STATIC Layer-0 only — yara, import_capability, tool_artifact. sigma, lolbin and "
            "network_dga consume a sandbox report and are excluded; they are also the layers "
            "weighted below yara, so their absence does not flatter the result."
        ),
        "samples_seen": len(files),
        "samples_parsed": parsed,
        "samples_with_evidence": n,
        "shipped_layer_weights": dict(LAYER_WEIGHTS),
        "shipped_cross_layer_multipliers": dict(CROSS_LAYER_MULTIPLIERS),
        "contribution": contribution,
        "pairwise_technique_overlap": dict(overlap_total),
        "corroboration_histogram_sources_per_technique": dict(sorted(corr_hist.items())),
        # The cascade groups by DOMAIN, not by source, and tool_artifact shares
        # yara's domain. This is the histogram that governs `is_corroborated`.
        "corroboration_histogram_domains_per_technique": dict(sorted(domain_corr_hist.items())),
        "techniques_emitted_by_domain": dict(domain_yield),
    }

    if all_isrs:
        print("running weight sensitivity ...", flush=True)
        result["weight_sensitivity"] = weight_sensitivity(
            all_isrs, build_perturbations(), top_n=args.top_n
        )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2)[:4000])
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
