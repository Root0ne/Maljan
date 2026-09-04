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

ROOT = Path(__file__).resolve().parents[2]


def test_a_real_cape_report_sniffs_as_cape2():
    path = sorted((ROOT / "data" / "cape_reports").glob("*.json"))[0]
    assert sniff_format(json.loads(path.read_text(encoding="utf-8"))) == "cape2"


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
