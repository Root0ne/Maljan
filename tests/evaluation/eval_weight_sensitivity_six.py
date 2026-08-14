"""C2b — do the cascade's constants matter once the sandbox is in play?

§1.10 perturbed the eleven cascade constants over **three static Layer-0 sources**
and found the top-10 ranking moving on 10.6–27.5% of samples and the corroborated
set moving on **0.0%**, every time. Part of that is structural and needs no
re-run: ``is_corroborated`` is ``len(contributing_layers) >= 2`` and never reads
``LAYER_WEIGHTS``, so no weight change can move it, ever.

The part that does need a re-run is §1.10's own caveat, stated there and never
discharged:

> 1,184 techniques were seen by exactly one domain and 163 by two: **87.9% of
> techniques are single-source *before the sandbox is in play*.**

That is the whole question. Corroboration needs two **domains**, and the three
static sources collapse into two (``tool_artifact`` emits on yara's domain, which
is why §1.10 found it unable to contribute agreement at all). ``sigma_layer``
fires on **94 of 97** archived reports at weight 0.55 and carries a *different*
domain — it is the first source in this system that can create cross-domain
corroboration where the static three could not. If the corroborated set is going
to move at all, it moves here or nowhere.

So this repeats §1.10's five perturbations over the **six-source** assembly,
built exactly as ``eval_layer0_six.py`` builds it, from the 97 archived sandbox
reports on disk. That makes it a *dynamic* Layer-0 study and retires the scope
limitation ``eval_layer0_contribution.py`` states in its own docstring.

**A prediction, written before the run.** The corroborated set should now move
under perturbation for the first time — not because the weights became
load-bearing (they cannot; see the structural argument above) but because adding
a second domain is what makes corroboration possible at all. If it still moves on
**0.0%**, the conclusion is stronger than §1.10's and different in kind: the
cascade's agreement signal is inert not for want of a second domain but by
construction.

Deterministic: no LLM, no network, no sandbox. Reads `data/cape_reports/`.

Run:  .venv/bin/python tests/evaluation/eval_weight_sensitivity_six.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from tests.evaluation.eval_layer0_contribution import (  # noqa: E402
    build_perturbations,
    collect_isrs,
    weight_sensitivity,
)
from tests.evaluation.eval_layer0_six import (  # noqa: E402
    REPORTS_DIR,
    SAMPLES_DIR,
    build_dynamic_isrs,
)

OUT_JSON = _HERE / "weight_sensitivity_six.json"
OUT_MD = _HERE / "weight_sensitivity_six.md"


def static_isrs_for(sha: str, yara_layer: Any, tool_catalog: str) -> dict[str, Any]:
    """The three offline sources for one sample, via §1.10's own assembly.

    Reusing ``collect_isrs`` rather than rebuilding it is the point: if this study
    constructed the static half differently from the study it is extending, any
    difference in result would be uninterpretable — the two would no longer share
    a baseline.
    """
    path = next((p for p in SAMPLES_DIR.glob(f"{sha}*") if p.is_file()), None)
    if path is None:
        return {}
    try:
        return collect_isrs(path, yara_layer, tool_catalog)
    except Exception:  # noqa: BLE001 — an absent source is data, not a crash
        return {}


def domain_counts(all_isrs: list[dict[str, Any]]) -> dict[str, int]:
    """How many techniques are seen by one domain, two, three or more.

    §1.10's 87.9%-single-source figure is the number this study exists to revisit,
    so it is recomputed here rather than quoted.
    """
    buckets = {"1": 0, "2": 0, "3+": 0}
    for isrs in all_isrs:
        by_tid: dict[str, set[str]] = {}
        for isr in isrs.values():
            domain = str(getattr(isr, "domain", "") or "")
            for claim in getattr(isr, "claims", []) or []:
                tid = str(getattr(claim, "technique_id", "") or "").strip().upper()
                if tid:
                    by_tid.setdefault(tid, set()).add(domain)
        for domains in by_tid.values():
            key = "1" if len(domains) == 1 else "2" if len(domains) == 2 else "3+"
            buckets[key] += 1
    return buckets


def main() -> int:
    shas = sorted(p.stem for p in REPORTS_DIR.glob("*.json"))
    if not shas:
        print("no archived reports — nothing to do")
        return 1
    print(f"cohort: {len(shas)} archived reports", flush=True)

    # Built once and reused, as the pipeline does: recompiling 30 rules per sample
    # would make this a rule-compilation benchmark rather than a cascade study.
    from maljan.analysis.yara_layer import YaraLayer

    yara_layer: Any
    rules_path = _REPO_ROOT / "data" / "yara_ttp_rules.yaml"
    try:
        # ``from_yaml``, not the bare constructor: YaraLayer takes a compiled rule
        # list, and an empty layer would silently drop the heaviest static source
        # (weight 0.90) — leaving this study non-comparable with the §1.10 run it
        # exists to extend, while still printing a full-looking table.
        yara_layer = YaraLayer.from_yaml(str(rules_path))
    except Exception as exc:  # noqa: BLE001
        print(f"FATAL: yara layer unavailable ({type(exc).__name__}: {exc})")
        print("  Refusing to run: without yara this is not comparable to §1.10.")
        return 2
    tool_catalog = str(_REPO_ROOT / "data" / "tool_artifacts_v1.json")

    all_isrs: list[dict[str, Any]] = []
    with_dynamic = 0
    source_hits: dict[str, int] = {}
    for i, sha in enumerate(shas, 1):
        try:
            report = json.loads((REPORTS_DIR / f"{sha}.json").read_text())
        except Exception:  # noqa: BLE001
            continue
        platform = None
        isrs = static_isrs_for(sha, yara_layer, tool_catalog)
        dyn = build_dynamic_isrs(report, platform)
        if dyn:
            with_dynamic += 1
        isrs.update(dyn)
        if isrs:
            all_isrs.append(isrs)
            for name in isrs:
                source_hits[name] = source_hits.get(name, 0) + 1
        if i % 20 == 0:
            print(f"  {i}/{len(shas)} assembled", flush=True)

    n = len(all_isrs)
    if not n:
        print("no sample produced any Layer-0 claim — aborting")
        return 1

    buckets = domain_counts(all_isrs)
    total_tids = sum(buckets.values())
    single_share = buckets["1"] / total_tids if total_tids else 0.0
    results = weight_sensitivity(all_isrs, build_perturbations(), top_n=10)

    lines = [
        "# C2b — cascade weight sensitivity with the dynamic layer in play",
        "",
        f"{n} samples assembled from {len(shas)} archived reports; "
        f"{with_dynamic} carried at least one dynamic source.",
        "",
        "| source | samples where it produced a claim |",
        "|---|---|",
    ]
    for name, hits in sorted(source_hits.items(), key=lambda kv: -kv[1]):
        lines.append(f"| `{name}` | {hits}/{n} |")

    lines += [
        "",
        "## How many domains see each technique",
        "",
        "§1.10 measured **87.9% single-domain** over three static sources and named the sandbox as",
        "the missing ingredient. Recomputed here with six sources:",
        "",
        f"| exactly one domain | **{buckets['1']}** ({single_share:.1%}) |",
        "|---|---|",
        f"| two domains | {buckets['2']} |",
        f"| three or more | {buckets['3+']} |",
        "",
        "## Perturbing the eleven constants",
        "",
        "| perturbation | top-10 changed | corroborated set changed | net delta |",
        "|---|---|---|---|",
    ]
    for label, r in results.items():
        lines.append(
            f"| `{label}` | {r['samples_with_changed_top_n']}/{n} "
            f"({r['fraction_top_n_changed']:.1%}) | "
            f"**{r['samples_with_changed_corroborated_set']}/{n}** | "
            f"{r['net_corroborated_delta']:+d} |"
        )

    corr_moved = any(r["samples_with_changed_corroborated_set"] for r in results.values())
    lines += [""]
    if corr_moved:
        lines += [
            "**The corroborated set moves for the first time.** §1.10's 0.0% was a property of a",
            "two-domain evidence base, not of the cascade: with a genuine third domain in play the",
            "weights reach the agreement signal. What that signal then reaches is a separate",
            "question, and §3.27.1 answers it — the corroborated set is never read downstream.",
        ]
    else:
        lines += [
            "**The corroborated set still moves on 0.0%, and now the reason is exhausted.** §1.10",
            "left open whether its null came from having only two effective domains; that",
            "explanation is now spent — `sigma_layer` supplies a third on most of the cohort and",
            "nothing changes. `is_corroborated` is `len(contributing_layers) >= 2` and never",
            "consults `LAYER_WEIGHTS`, so the eleven constants cannot move it by construction, and",
            "the corpus was never what was hiding that.",
            "",
            "Taken with §3.27.1 the cascade is inert twice over. Its agreement flag is unreachable",
            "by its own weights. And its technique set — the one thing that *is* read downstream —",
            "reaches the artefact through a reconciliation step that restores whatever the judge",
            "omitted, so the judge cannot subtract from it and, across 80 arms, added nothing.",
        ]

    report_md = "\n".join(lines)
    print("\n" + report_md, flush=True)
    OUT_MD.write_text(report_md + "\n")
    OUT_JSON.write_text(
        json.dumps(
            {
                "schema": "weight-sensitivity-six/v1",
                "n_samples": n,
                "reports_available": len(shas),
                "samples_with_dynamic_source": with_dynamic,
                "source_hits": source_hits,
                "domain_buckets": buckets,
                "single_domain_share": round(single_share, 4),
                "perturbations": results,
            },
            indent=1,
        )
        + "\n"
    )
    print(f"\nwrote {OUT_MD.name} and {OUT_JSON.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
