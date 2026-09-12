"""The sandbox tools' answers, frozen over every CAPE fixture.

These answers are the whole downstream contract of a sandbox report now: what
an agent sees when it asks what ran, what it talked to, what the sandbox's own
signatures said, what was written to disk, which registry keys were touched,
which APIs were called, which mutexes were held and what was arranged to run
again. The report is assembled from
those answers, so freezing them over the real corpus
(``data/cape_reports/*.json``, 97 detonations) is what makes a change to the
provider layer visible instead of quietly reshaping every report.

The golden dumps for all 98 CAPE-shaped fixtures are committed (see
``tests/fixtures/golden/sandbox_tools``), but the raw source reports themselves
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

from maljan.providers.sandbox_tools import (
    sandbox_api_calls,
    sandbox_dropped_files,
    sandbox_mutexes,
    sandbox_network,
    sandbox_processes,
    sandbox_registry_ops,
    sandbox_services_and_tasks,
    sandbox_signatures,
)

ROOT = Path(__file__).resolve().parents[3]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "sandbox_tools"
CAPE_GLOBS: tuple[str, ...] = ("data/cape_reports/*.json", "data/samples/dynamic/sample_1.json")


def cape_reports() -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for pattern in CAPE_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                out.append((path.stem, raw))
    return out


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
def test_processes_match_the_golden(name: str):
    raw, expected = _load_case(name)
    assert sandbox_processes(raw) == expected["sandbox_processes"]


@pytest.mark.parametrize("name", _ALL_NAMES, ids=_ALL_NAMES)
def test_network_matches_the_golden(name: str):
    raw, expected = _load_case(name)
    assert sandbox_network(raw) == expected["sandbox_network"]


@pytest.mark.parametrize("name", _ALL_NAMES, ids=_ALL_NAMES)
def test_signatures_match_the_golden(name: str):
    raw, expected = _load_case(name)
    assert sandbox_signatures(raw) == expected["sandbox_signatures"]


@pytest.mark.parametrize("name", _ALL_NAMES, ids=_ALL_NAMES)
def test_dropped_files_match_the_golden(name: str):
    raw, expected = _load_case(name)
    assert sandbox_dropped_files(raw) == expected["sandbox_dropped_files"]


@pytest.mark.parametrize("name", _ALL_NAMES, ids=_ALL_NAMES)
def test_registry_ops_match_the_golden(name: str):
    raw, expected = _load_case(name)
    assert sandbox_registry_ops(raw) == expected["sandbox_registry_ops"]


@pytest.mark.parametrize("name", _ALL_NAMES, ids=_ALL_NAMES)
def test_api_calls_match_the_golden(name: str):
    raw, expected = _load_case(name)
    assert sandbox_api_calls(raw) == expected["sandbox_api_calls"]


@pytest.mark.parametrize("name", _ALL_NAMES, ids=_ALL_NAMES)
def test_mutexes_match_the_golden(name: str):
    raw, expected = _load_case(name)
    assert sandbox_mutexes(raw) == expected["sandbox_mutexes"]


@pytest.mark.parametrize("name", _ALL_NAMES, ids=_ALL_NAMES)
def test_services_and_tasks_match_the_golden(name: str):
    raw, expected = _load_case(name)
    assert sandbox_services_and_tasks(raw) == expected["sandbox_services_and_tasks"]
