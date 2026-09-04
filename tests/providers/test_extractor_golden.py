"""``build_dynamic_behavior`` and ``build_network_iocs`` over every CAPE fixture.

These two functions are the whole downstream contract of the sandbox report:
the report's dynamic section, its IOC tables and the DGA / LOLBin Layer-0
scanners all read what they produce. Freezing their output over the real
corpus (``data/cape_reports/*.json``, 97 detonations) is what lets the provider
layer be introduced under the raw dicts without anybody having to trust a
normalisation function.

The golden dumps for all 98 CAPE-shaped fixtures are committed (see
``tests/fixtures/golden/extractors``), but the raw source reports themselves
are git-ignored — ``data/cape_reports/`` (97 files) exists only on the machine
that captured them; only ``data/samples/dynamic/sample_1.json`` is tracked.
Anywhere else (CI included), a case whose raw source is missing is skipped by
name rather than failed, so CI still exercises the tracked sample while this
machine exercises the full corpus.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from maljan.extractors.dynamic_extractor import build_dynamic_behavior
from maljan.extractors.network_extractor import build_network_iocs

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "extractors"
CAPE_GLOBS: tuple[str, ...] = ("data/cape_reports/*.json", "data/samples/dynamic/sample_1.json")


def cape_reports() -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for pattern in CAPE_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                out.append((path.stem, raw))
    return out


def dump(model: Any) -> Any:
    return None if model is None else model.model_dump(mode="json")


def _raw_path_for(name: str) -> Path | None:
    for pattern in CAPE_GLOBS:
        for path in ROOT.glob(pattern):
            if path.stem == name:
                return path
    return None


def _load_case(name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    raw_path = _raw_path_for(name)
    if raw_path is None:
        pytest.skip(f"raw CAPE report missing: {name}.json (not found under {CAPE_GLOBS})")
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    expected = json.loads((GOLDEN / f"{name}.json").read_text(encoding="utf-8"))
    return raw, expected


_ALL_NAMES: list[str] = sorted(p.stem for p in GOLDEN.glob("*.json"))


def test_the_corpus_is_present():
    assert len(_ALL_NAMES) >= 90, "CAPE golden corpus is missing; goldens cannot be trusted"


@pytest.mark.parametrize("name", _ALL_NAMES, ids=_ALL_NAMES)
def test_dynamic_behavior_matches_the_golden(name: str):
    raw, expected = _load_case(name)
    assert dump(build_dynamic_behavior(raw)) == expected["dynamic_behavior"]


@pytest.mark.parametrize("name", _ALL_NAMES, ids=_ALL_NAMES)
def test_network_iocs_matches_the_golden(name: str):
    raw, expected = _load_case(name)
    assert dump(build_network_iocs(raw)) == expected["network_iocs"]
