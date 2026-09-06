"""Format sniffing, most specific first.

A Triage overview carries ``analysis.score`` and ``tasks``; a CAPE report
carries ``info.version`` with "CAPE" in it or the CAPE-only top-level ``CAPE``
key; Cuckoo is the fallback for a report that has ``behavior`` and ``info`` but
neither marker. Order matters: a Triage report has a ``signatures`` list too.
"""

from __future__ import annotations

import json
from pathlib import Path

from maljan.providers.sandbox.formats import sniff_format
from tests.providers._cape_fixture import FIXTURE_PATH, first_cape_report

ROOT = Path(__file__).resolve().parents[2]


def test_a_real_cape_report_sniffs_as_cape2():
    assert sniff_format(first_cape_report()) == "cape2"


def test_the_committed_fixture_itself_sniffs_as_cape2():
    """Exercises the fallback shape directly, even on a machine that has the
    real reports and would otherwise never touch the committed fixture."""
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    assert sniff_format(payload) == "cape2"


def test_a_triage_overview_sniffs_as_triage():
    payload = {
        "version": "0.3.0",
        "sample": {"id": "260903-abcdef", "target": "x.exe", "sha256": "a" * 64},
        "tasks": [{"name": "behavioral1", "kind": "behavioral"}],
        "analysis": {"score": 10, "family": ["qakbot"]},
        "signatures": [{"name": "s", "score": 10}],
    }
    assert sniff_format(payload) == "triage"


def test_a_cuckoo_report_sniffs_as_cuckoo():
    payload = {
        "info": {"version": "2.0.7", "id": 12},
        "behavior": {"processes": [], "generic": []},
        "signatures": [],
    }
    assert sniff_format(payload) == "cuckoo"


def test_anything_else_is_unknown():
    assert sniff_format({"hello": "world"}) == "unknown"
    assert sniff_format({}) == "unknown"
