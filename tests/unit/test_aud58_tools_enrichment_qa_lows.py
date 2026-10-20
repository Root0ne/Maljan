"""AUD-58 TB-12..TB-18: the Low findings of the tools, enrichment and qa audit."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from maljan.analysis.disclosure import EnrichmentAsks
from maljan.enrichment.declared import ReadySource, SourceAsker, effective_sources
from maljan.enrichment.whois_client import _find_first_autnum
from maljan.qa.fp_linter import lint_report
from maljan.tools import emulated_strings, knowledge
from maljan.tools.api_hashes import _values
from maljan.utils.json_cleaner import extract_json, safe_parse_json


def test_tb12_an_entity_handle_that_merely_starts_with_as_is_no_autnum() -> None:
    assert _find_first_autnum({"entities": [{"handle": "ASSOCIATES-ARIN"}]}) is None
    assert _find_first_autnum({"entities": [{"handle": "ASH-1"}, {"handle": "AS15169"}]}) == "15169"


def test_tb13_a_gate_that_cannot_score_gives_no_answer_not_a_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Index:
        def validate_and_score(self, tid: str, text: str) -> float:
            raise RuntimeError("no such id")

    monkeypatch.setattr(knowledge, "index_is_warm", lambda: True)
    monkeypatch.setattr(knowledge, "_hybrid_index", lambda: (_Index(), ""))
    monkeypatch.setattr(knowledge, "resolve_technique", lambda text, k=5: {"candidates": []})
    assert knowledge.technique_alignment("it beacons", "T1071") is None


def test_tb14_a_digit_only_hash_is_read_as_hex_too() -> None:
    assert sorted(_values("12345678")) == sorted([0x12345678, 12345678])
    assert _values("01234567") == [0x01234567]
    assert _values("0x1234ABCD") == [0x1234ABCD]
    assert _values("4294967295") == [4294967295]
    assert _values(305419896) == [305419896]


def test_tb15_a_check_that_failed_does_not_ground_the_section(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _fails(section: Any) -> bool:
        raise RuntimeError("boom")

    monkeypatch.setattr("maljan.reporting.ledger_report.section_is_grounded", _fails)
    report = SimpleNamespace(
        capability_matrix=[],
        defensive_recommendations=[],
        executive_summary="",
        attribution=None,
        stix_bundle_extended=None,
        run_summary={},
        sections=[SimpleNamespace(evidence_ids=["ev_1"], source="")],
        ttp_mappings=[],
    )
    assert "C6" in {w.rule for w in lint_report(report, "android")}


def test_tb16_floss_is_not_started_with_a_preexec_function(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}
    real = subprocess.Popen

    def _spy(*args: Any, **kwargs: Any) -> Any:
        seen.update(kwargs)
        return real(*args, **kwargs)

    limited: list[int] = []
    monkeypatch.setattr(emulated_strings.subprocess, "Popen", _spy)
    monkeypatch.setattr(
        emulated_strings.resource, "prlimit", lambda pid, which, limit: limited.append(pid)
    )
    emulated_strings._spawn(["true"], 10.0, str(tmp_path))
    assert "preexec_fn" not in seen
    assert len(limited) == 1


def test_tb17_prose_brackets_before_the_payload_do_not_hide_it() -> None:
    text = 'As noted in [1], here is the answer: {"claims": [1, 2]}'
    assert extract_json(text) == '{"claims": [1, 2]}'
    assert safe_parse_json(text) == {"claims": [1, 2]}
    assert safe_parse_json('[{"a": 1}]') == [{"a": 1}]
    # A broken payload stays whole: its own parts are not another payload.
    broken = '{"a": ["x"], "b": oops}'
    assert extract_json(broken) == broken
    cut = '{"items": [{"k": 1}, {"k": 2}, {"k"'
    assert extract_json(cut) == cut


def _ready() -> ReadySource:
    source = effective_sources({"virustotal": {"rate_limit_seconds": 0.0}})["virustotal"]
    return ReadySource(key="virustotal", source=source, credential="-".join(("vt", "k")))


@pytest.mark.asyncio
async def test_tb18_an_error_answer_does_not_settle_a_question_as_answered() -> None:
    asks = EnrichmentAsks()
    with patch("maljan.enrichment.whois_client._try_ipwhois", return_value=None):
        transport = httpx.MockTransport(lambda request: httpx.Response(429))
        async with httpx.AsyncClient(transport=transport) as http:
            asker = SourceAsker(http=http, on_ask=asks)
            assert await asker.ask(_ready(), "domain", "evil.example.com") is None
    (row,) = asks.rows()
    assert row["failed"] == 0 and row["errored"] == 1
