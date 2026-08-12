"""All six Layer-0 sources on one cohort — the half of §3.1 that needed a sandbox.

`eval_layer0_contribution.py` measured three sources (`yara_layer`,
`import_capability`, `tool_artifact`) and said so in its own scope note: the
other three consume a sandbox report and could not run. They are now runnable
offline, because the cohort's CAPE reports are archived and the production
builders take a **report dict**, not a live connection:

    sigma_layer   build_events_from_sandbox → scan_events → to_isr
    lolbin        build_lolbin_isr(report)
    network_dga   build_dga_isr(build_network_iocs(report))

That assembly is copied from `pipeline/nodes.py`, not reinvented, so this
measures what production computes rather than a plausible imitation of it.

**Why this is a real test and not a confirmation.** §1.10 found that varying the
corroborated set changes the final verdict in 0 of 15 cases — measured with three
static sources. The three missing ones include `sigma` at weight **0.55**, above
`static` at 0.35 and below only `yara`. A null obtained without the second-heaviest
layer is not evidence about the cascade; it is evidence about a cascade that was
missing a layer.

Deterministic end to end: no LLM, no live sandbox, no network. Runs in minutes.

Run:  .venv/bin/python tests/evaluation/eval_layer0_six.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src"))

REPORTS_DIR = _REPO_ROOT / "data" / "cape_reports"
SAMPLES_DIR = _REPO_ROOT / "data" / "samples"
OUT = _HERE / "layer0_six.json"

DYNAMIC_SOURCES = ("sigma_layer", "lolbin", "network_dga")
STATIC_SOURCES = ("yara_layer", "import_capability", "tool_artifact")


def build_dynamic_isrs(report: dict[str, Any], platform: str | None) -> dict[str, Any]:
    """The three sandbox-fed Layer-0 sources, assembled as `nodes.py` assembles them."""
    from maljan.analysis.lolbin_layer import build_lolbin_isr
    from maljan.analysis.sigma_layer import build_events_from_sandbox
    from maljan.core.config import get_settings
    from maljan.core.container import ServiceContainer
    from maljan.extractors.network_extractor import build_dga_isr, build_network_iocs

    isrs: dict[str, Any] = {}

    try:
        container = ServiceContainer(config=get_settings())
        sigma_layer = container.get_sigma_layer()
        if sigma_layer.rule_count > 0:
            events = build_events_from_sandbox(report)
            if events:
                matches = sigma_layer.scan_events(events, "sandbox", platform)
                if matches:
                    isr = sigma_layer.to_isr(matches)
                    if isr is not None and isr.claims:
                        isrs["sigma_layer"] = isr
    except Exception as exc:  # noqa: BLE001 — a source that fails is absent, as in production
        print(f"    sigma: {type(exc).__name__}: {str(exc)[:70]}", flush=True)

    try:
        isr = build_lolbin_isr(report)
        if isr is not None and isr.claims:
            isrs["lolbin"] = isr
    except Exception as exc:  # noqa: BLE001
        print(f"    lolbin: {type(exc).__name__}: {str(exc)[:70]}", flush=True)

    try:
        isr = build_dga_isr(build_network_iocs(report))
        if isr is not None and isr.claims:
            isrs["network_dga"] = isr
    except Exception as exc:  # noqa: BLE001
        print(f"    dga: {type(exc).__name__}: {str(exc)[:70]}", flush=True)

    return isrs


def tids(isr: Any) -> set[str]:
    out: set[str] = set()
    for claim in getattr(isr, "claims", []):
        raw = getattr(claim, "technique_id", None)
        if raw is None:
            continue
        t = str(raw).strip().upper()
        if t and t != "NONE":
            out.add(t)
    return out


def main() -> int:
    from maljan.analysis.ttp_cascade import TTPCascadeEngine

    shas = sorted(p.stem for p in REPORTS_DIR.glob("*.json"))
    print(f"cohort: {len(shas)} samples with an archived report", flush=True)

    engine = TTPCascadeEngine()
    per_sample: list[dict[str, Any]] = []
    fired = dict.fromkeys(DYNAMIC_SOURCES, 0)
    unique_credit = dict.fromkeys(DYNAMIC_SOURCES, 0)

    for i, sha in enumerate(shas, 1):
        report = json.loads((REPORTS_DIR / f"{sha}.json").read_text())
        platform = "windows"
        dyn = build_dynamic_isrs(report, platform)
        for name in DYNAMIC_SOURCES:
            if name in dyn:
                fired[name] += 1

        # What each dynamic source contributes that no other dynamic source found.
        for name in DYNAMIC_SOURCES:
            if name not in dyn:
                continue
            mine = tids(dyn[name])
            others: set[str] = set()
            for other, isr in dyn.items():
                if other != name:
                    others |= tids(isr)
            if mine - others:
                unique_credit[name] += 1

        summary = engine.compute(dyn, sample_platform=platform) if dyn else None
        corroborated = getattr(summary, "corroborated_count", None) if summary else 0
        all_tids: set[str] = set()
        for isr in dyn.values():
            all_tids |= tids(isr)

        per_sample.append(
            {
                "sha256": sha,
                "sources_fired": sorted(dyn),
                "n_dynamic_techniques": len(all_tids),
                "corroborated": corroborated,
            }
        )
        if i % 10 == 0 or i == len(shas):
            print(f"  [{i}/{len(shas)}]", flush=True)

    n = len(shas)
    print("\ndynamic Layer-0 firing rates over the archived cohort:")
    for name in DYNAMIC_SOURCES:
        rate = fired[name] / n if n else 0.0
        uniq = unique_credit[name]
        print(
            f"  {name:14s} fires on {fired[name]:3d}/{n} = {rate:6.1%}"
            f"   unique-technique credit on {uniq}"
        )

    OUT.write_text(
        json.dumps(
            {
                "schema": "layer0-six/v1",
                "scope": (
                    "The three sandbox-fed Layer-0 sources over the archived cohort. "
                    "Static sources are measured separately in layer0_contribution.json; "
                    "this file exists to close the half that needed a sandbox report."
                ),
                "n": n,
                "fired": fired,
                "unique_technique_credit": unique_credit,
                "per_sample": per_sample,
            },
            indent=1,
        )
    )
    print(f"\nwrote {OUT.relative_to(_REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
