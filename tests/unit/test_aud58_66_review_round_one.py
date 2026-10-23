"""AUD-58/66 review round 1: the reader keeps dev's payload, and the leftovers.

TB-17 (``extract_json``) must read every answer dev read the intended payload
from the same way; TB-14 keeps one entry per given hash string; TB-16 tracks the
child whether or not its memory cap could be set; TB-18 has a state for an
error status (it arrived); the json readers survive nesting past the
interpreter; the CAPE reader takes a non-string pcap path as none.
"""

from __future__ import annotations

import struct
import subprocess
from pathlib import Path
from typing import Any

import httpx
import pytest

from maljan.analysis.disclosure import EnrichmentAsks
from maljan.enrichment.declared import ReadySource, SourceAsker, effective_sources
from maljan.schemas.sandbox_report import cape_report_to_sandbox_report
from maljan.tools import api_hashes, emulated_strings
from maljan.tools.api_hashes import resolve_api_hashes
from maljan.utils.json_cleaner import extract_json, json_decode_error, safe_parse_json
from tests.unit.tools.synthetic_pe import SyntheticPE

OBJ = '{"verdict": "malicious", "claims": [{"id": 1}], "score": 0.9}'


# TB-17 -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "want"),
    [
        # (a) a stray quote in the prose does not hide the payload.
        ('The process wrote "C:\\x.exe and then:\n' + OBJ, OBJ),
        ('He typed a 3.5" disk.\n' + OBJ, OBJ),
        (
            'The value "x is odd ["T1055", "T1071"]\nExample: {"verdict": "benign"}',
            '["T1055", "T1071"]',
        ),
        # (c) a payload that begins a line, a scalar list or an empty one included, wins.
        ('Thought: the key "a" matters.\n[]\nExample: {"verdict": "benign"}', "[]"),
        (
            '```json\n["T1055", "T1071"]\n```\nEach item maps to {"id": "Txxxx"}',
            '["T1055", "T1071"]',
        ),
        ('```json\n[]\n```\nNo findings; a finding would look like {"id": 1}', "[]"),
        # a citation marker inside a line of prose is not the payload.
        ("As noted in [1], " + OBJ, OBJ),
        ("Scores in [0, 1]: " + OBJ, OBJ),
        # prose brackets that do not read are passed.
        ("I will use {placeholder}. " + OBJ, OBJ),
        ("Note: [see below]\n" + OBJ, OBJ),
    ],
)
def test_tb17_the_payload_is_the_one_dev_read(text: str, want: str) -> None:
    assert extract_json(text) == want


@pytest.mark.parametrize(
    "text",
    [
        # (b) a broken payload is returned to the repair and the decode error, not skipped.
        '{"verdict": malicious}\nExample: {"verdict": "benign"}',
        'Final: {"verdict": malicious}\nExample: {"verdict": "benign"}',
        '```json\n{"verdict": "malicious",, "a": 1}\n```\nFor reference {"verdict": "benign"}',
    ],
)
def test_tb17_a_broken_payload_is_not_skipped_for_a_later_example(text: str) -> None:
    assert safe_parse_json(text) is None
    assert json_decode_error(text) is not None


# json readers, RecursionError ----------------------------------------------------


def test_the_json_readers_survive_nesting_past_the_interpreter() -> None:
    deep = "[" * 100_000 + "]" * 100_000
    assert safe_parse_json(deep) is None
    assert json_decode_error(deep) is None


# TB-14 -----------------------------------------------------------------------


def test_tb14_one_entry_per_given_string_unresolved_only_when_no_reading_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = SyntheticPE()
    image.put("data", 0x40, struct.pack("<I", 0x12345678))
    path = tmp_path / "sample.exe"
    path.write_bytes(image.build())
    real = api_hashes._readings

    def _only_hex(table: Any, value: int) -> Any:
        if value == 0x12345678:
            return [{"algorithm": "x", "name": "N", "dlls": []}]
        return real(table, value)

    monkeypatch.setattr(api_hashes, "_readings", _only_hex)
    answer = resolve_api_hashes(str(path), hashes=["12345678", "99999999", "0x00000123"])
    assert [row["value"] for row in answer["hits"]] == ["0x12345678"]
    assert answer["unresolved"] == ["99999999", "0x00000123"]
    assert answer["candidates"] == {"given": 3}


# TB-16 -----------------------------------------------------------------------


@pytest.mark.parametrize("failure", ["missing", "refused"])
def test_tb16_a_cap_that_cannot_be_set_still_tracks_the_child_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    from maljan.tools import children

    if failure == "missing":
        monkeypatch.delattr(emulated_strings.resource, "prlimit", raising=False)
    else:

        def _refused(*_args: Any) -> None:
            raise PermissionError("no")

        monkeypatch.setattr(emulated_strings.resource, "prlimit", _refused)
    registered: list[Any] = []
    real = children.register
    monkeypatch.setattr(
        children, "register", lambda killer: registered.append(killer) or real(killer)
    )
    finished = emulated_strings._spawn(["true"], 10.0, str(tmp_path))
    assert registered, "the child is tracked whatever the cap did"
    assert getattr(finished, "memory_cap_applied", True) is False
    assert isinstance(finished, subprocess.CompletedProcess)


def test_tb16_the_result_says_the_cap_was_not_applied() -> None:
    finished = subprocess.CompletedProcess(["floss"], 0, "{}", "")
    finished.memory_cap_applied = False  # type: ignore[attr-defined]
    document = emulated_strings._emulate(
        "floss", Path("/x"), 4, None, lambda argv, timeout: finished
    )
    assert isinstance(document, dict)
    assert emulated_strings._meta(document)["memory_cap"] == emulated_strings.NO_MEMORY_CAP


# TB-18 -----------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [429, 500, 503])
async def test_tb18_an_error_status_proves_arrival_and_is_not_counted_failed(status: int) -> None:
    asks = EnrichmentAsks()
    source = effective_sources({"virustotal": {"rate_limit_seconds": 0.0}})["virustotal"]
    ready = ReadySource(key="virustotal", source=source, credential="-".join(("vt", "k")))
    transport = httpx.MockTransport(lambda request: httpx.Response(status))
    async with httpx.AsyncClient(transport=transport) as http:
        assert (
            await SourceAsker(http=http, on_ask=asks).ask(ready, "domain", "evil.example.com")
            is None
        )
    (row,) = asks.rows()
    assert row["failed"] == 0 and row["errored"] == 1


def test_tb18_the_disclosure_says_it_arrived() -> None:
    from maljan.analysis.disclosure import _asked_parts

    row = {"source": "x", "host": "h.example", "kinds": {"domain": 2}, "failed": 1, "errored": 1}
    said = _asked_parts([row], lambda text: text)
    assert "1 of them failed in transport or did not finish and may have arrived" in said
    assert "1 of them answered with an error status (it arrived)" in said


# Review round 2 --------------------------------------------------------------


def test_tb17_a_long_answer_of_prose_markers_is_read_in_linear_time() -> None:
    import time

    def best_of_three(size: int) -> float:
        text = "x [1] " * (size // 6)
        times = []
        for _ in range(3):
            started = time.perf_counter()
            extract_json(text)
            times.append(time.perf_counter() - started)
        return min(times)

    # Four times the text: a linear reading takes about four times as long, a
    # quadratic one sixteen. A ratio, not a wall-clock bound, so a slow
    # machine does not fail it.
    small, large = best_of_three(512 * 1024), best_of_three(2 * 1024 * 1024)
    assert large < 8 * max(small, 1e-3)


def test_l1_an_uppercase_hash_is_still_the_runs_own_sample() -> None:
    from maljan.memory.attck_case_index import AttckCaseIndex

    own = "ab" * 32
    other = "cd" * 32
    index = AttckCaseIndex.from_records(
        [
            {"sample_id": own, "summary_text": "beacon network", "technique_ids": ["T1055"]},
            {"sample_id": other, "summary_text": "beacon network", "technique_ids": ["T1071"]},
        ]
    )
    found = index.search("beacon network", 5, 0.0, exclude_sample_id=own.upper())
    assert [n.sample_id for n in found] == [other]


# L5 --------------------------------------------------------------------------


@pytest.mark.parametrize("wrong", [7, ["x"], {"a": 1}, ""])
def test_l5_a_pcap_path_that_is_not_text_is_none(wrong: Any) -> None:
    report = cape_report_to_sandbox_report(
        {"network": {"pcap_local_path": wrong}}, provider="cape", source_format="cape"
    )
    assert report.network.pcap_local_path is None
    kept = cape_report_to_sandbox_report(
        {"network": {"pcap_local_path": "/tmp/x.pcap"}}, provider="cape", source_format="cape"
    )
    assert kept.network.pcap_local_path == "/tmp/x.pcap"
