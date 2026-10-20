"""The sighting search costs the entries a value is held in, not every entry (RC-18)."""

from __future__ import annotations

from typing import Any

import pytest

from maljan.agents import _indicator_denylists
from maljan.reporting.ledger_projection import tool_sightings
from maljan.schemas.evidence import EvidenceCounter
from tests.unit._ledger_helpers import entry


def _ledger(n: int) -> list[Any]:
    counter = EvidenceCounter()
    return [
        entry("strings", f"host-{i}.example.net and host-{(i + 1) % n}.example.net", counter)
        for i in range(n)
    ]


def test_each_value_names_the_entries_that_hold_it() -> None:
    ledger = _ledger(6)
    values = [("domain", f"host-{i}.example.net") for i in range(6)]
    seen, queried = tool_sightings(ledger, values)
    for i in range(6):
        held = {eid for eid, _tool in seen[f"host-{i}.example.net"]}
        assert held == {ledger[i].id, ledger[(i - 1) % 6].id}
    assert all(not rows for rows in queried.values())


def test_the_work_is_not_a_product(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"n": 0}
    real = _indicator_denylists.whole_value_in

    def counting(literal: str, haystack: str) -> bool:
        calls["n"] += 1
        return real(literal, haystack)

    monkeypatch.setattr(_indicator_denylists, "whole_value_in", counting)
    n = 200
    seen, _ = tool_sightings(_ledger(n), [("domain", f"host-{i}.example.net") for i in range(n)])
    assert all(len(rows) == 2 for rows in seen.values())
    assert calls["n"] < n * 10
