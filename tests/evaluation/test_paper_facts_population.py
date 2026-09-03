"""The paper gate refuses an artefact whose denominator shrank unexplained.

``paper_facts.check_population`` is what stands between a harness that silently
drops samples and a paper number that quietly moved. It must also stay inert on
artefacts written before the population field existed.
"""

from __future__ import annotations

import pytest

from tests.evaluation import paper_facts as pf


def test_population_gate() -> None:
    pf.check_population("x.json", {"samples": 3})  # no population: untouched
    pf.check_population(
        "x.json",
        {"population": {"attempted": 5, "parsed": 5, "scored": 5, "dropped": {}}},
    )
    pf.check_population(
        "x.json",
        {"population": {"attempted": 5, "parsed": 4, "scored": 3, "dropped": {"a": 2}}},
    )
    with pytest.raises(pf.FactError):
        pf.check_population(
            "x.json",
            {"population": {"attempted": 5, "parsed": 4, "scored": 3, "dropped": {}}},
        )
    with pytest.raises(pf.FactError):
        pf.check_population("x.json", {"population": {"attempted": 5}})  # missing "scored"
