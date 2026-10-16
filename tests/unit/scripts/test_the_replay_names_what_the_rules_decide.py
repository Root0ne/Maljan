"""The replay re-runs the platform's deterministic rules over a stored run, and only reads it.

A tiny stored run (``tests/fixtures/replay/tiny``) is replayed in this process
and each producer's codes are the ones its answers raise under today's rules:
the analysts' answers and claims in force, the judge's bundle, the narrative,
a composer section and a tool call. The replay is the same twice, leaves every
file of the run as it was, reaches no network, prints no claim text unless
asked, and names what it could not replay. Two records of one run are told
apart by every code they gained or lost and every report value that moved.
"""

from __future__ import annotations

import copy
import json
import socket
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from scripts.replay import run as replay_cli
from scripts.replay.compare import diff_records, differs
from scripts.replay.database import JobRows, jsonable, write_run
from scripts.replay.guard import ReplayRefused, replay_environment
from scripts.replay.output import render_diff, render_record
from scripts.replay.rules import REPLAY_FORMAT, replay_run
from scripts.replay.stored import StoredRunChanged, check_unchanged, digests, read_run

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "replay" / "tiny"

# What each producer raises over the tiny run under today's rules.
EXPECTED_TOTALS: dict[str, dict[str, int]] = {
    "answers": {
        "attck.absence_claim": 1,
        "attck.unknown_id": 1,
        "isr.claim_without_confidence": 1,
        "isr.technique_line_unread": 1,
        "isr.ungrounded_technique": 1,
    },
    "claims_in_force": {"attck.claim_does_not_describe": 1},
    "judge": {
        "stix.credit_without_claim": 1,
        "stix.ungrounded_indicator": 1,
        "stix.unknown_technique": 1,
    },
    "narrative": {
        "narrative.schema": 1,
        "narrative.ungrounded_finding": 1,
        "narrative.unpublished_technique": 1,
    },
    "composer": {"report.citation_not_evidence": 1},
    "tool": {"tool.argument_names_its_parameter": 1},
    "fp_linter": {"C7": 1},
}

# Sentences the analysts wrote in the tiny run: none is printed without the text.
CLAIM_SENTENCES = (
    "Its configuration strings are XOR-encoded",
    "Process injection is not present",
    "It registers a scheduled task named Updater",
    "The file has four sections",
)


@pytest.fixture(scope="module")
def record() -> dict[str, Any]:
    return replay_run(read_run(FIXTURE))


def _flags(entry: dict[str, Any]) -> list[dict[str, Any]]:
    return [{k: v for k, v in flag.items() if k != "message"} for flag in entry["flags"]]


def test_the_tiny_run_replays_to_its_expected_codes(record: dict[str, Any]) -> None:
    assert record["format"] == REPLAY_FORMAT
    assert record["totals"] == EXPECTED_TOTALS

    static = record["analysts"]["static"]
    (answer,) = [a for a in static["answers"] if a["replayed"]]
    assert (answer["answer"], answer["source"], answer["in_force"]) == (
        "round 1",
        "agent_reports",
        True,
    )
    assert answer["claims"] == 6
    flagged = _flags(answer)
    # An entry the analyst's own call made after this answer was written is
    # not one the answer could cite.
    assert {
        "code": "isr.ungrounded_technique",
        "path": "static.claims[5]",
        "subject": "T1140",
        "entries": ["ev_0004"],
    } in flagged
    # The claim of T1027 cites no entry, and the analyst's findings, read back
    # from the stored Findings table, cite one for T1027: it is not asked.
    assert answer["findings"] == 2
    assert not [f for f in flagged if f.get("path") == "static.claims[1]"]
    assert {
        "code": "attck.unknown_id",
        "path": "static.claims[2]",
        "subject": "T9999",
        "entries": ["ev_0002"],
    } in flagged
    assert {
        "code": "attck.absence_claim",
        "path": "static.claims[3]",
        "subject": "T1055",
        "entries": ["ev_0002"],
    } in flagged
    assert _flags(static["in_force"]) == [
        {
            "code": "attck.claim_does_not_describe",
            "path": "static.claims[2]",
            "subject": "T1105",
            "entries": ["ev_0001"],
        }
    ]

    assert record["judge"]["indicators_dropped"] == 1
    assert record["tool"]["flags"] == [
        {
            "code": "tool.argument_names_its_parameter",
            "entries": ["ev_0002"],
            "tool": "strings",
            "arguments": ["pattern"],
        }
    ]

    report = record["report"]
    assert (report["verdict"], report["severity"], report["confidence"]) == (
        "Malware",
        "Medium",
        0.8,
    )
    published = {tid: row["published"] for tid, row in report["techniques"].items()}
    assert published == {"T1027": True, "T1055": False, "T1105": True, "T9998": False}
    assert report["export"]["attack_patterns"] == ["T1027", "T1105"]
    assert report["claims_not_discussed"] == {"static": [3]}
    assert report["detection_rules"] == {"yara": 1}


def test_what_the_stored_run_cannot_give_is_named(record: dict[str, Any]) -> None:
    named = {(row["part"], row["why"]) for row in record["not_replayed"]}
    assert ("analyst network round 1", "stored truncated at 111 characters") in named
    assert (
        "analyst static round 0",
        "stored as the platform's summary of its claims, not as the analyst wrote it",
    ) in named
    parts = {part for part, _why in named}
    assert {"analysts", "judge", "composer", "judge evidence", "report"} <= parts
    network = record["analysts"]["network"]["answers"]
    assert [(a["answer"], a["replayed"]) for a in network] == [
        ("round 0", False),
        ("round 1", False),
        ("round 2", True),
    ]


def test_a_replay_is_deterministic_and_leaves_the_run_unchanged(record: dict[str, Any]) -> None:
    before = digests(FIXTURE)
    again = replay_run(read_run(FIXTURE))
    assert json.dumps(again, sort_keys=True) == json.dumps(record, sort_keys=True)
    assert digests(FIXTURE) == before


def test_a_run_changed_during_the_replay_fails_it() -> None:
    before = {"evidence.json": "a" * 64, "job.json": "b" * 64}
    check_unchanged(before, dict(before))
    with pytest.raises(StoredRunChanged, match=r"changed: evidence\.json"):
        check_unchanged(before, {**before, "evidence.json": "c" * 64})
    with pytest.raises(StoredRunChanged, match=r"added: notes\.txt"):
        check_unchanged(before, {**before, "notes.txt": "d" * 64})


def test_the_command_writes_its_record_and_never_inside_the_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "tiny.json"
    before = digests(FIXTURE)
    assert replay_cli.main([str(FIXTURE), "--json", str(out), "--quiet"]) == 0
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["totals"] == EXPECTED_TOTALS
    assert written["stored"]["files"] == before
    for flag, inside in (("--json", "record.json"), ("--work", "trees")):
        with pytest.raises(SystemExit) as ended:
            replay_cli.main([str(FIXTURE), flag, str(FIXTURE / inside), "--quiet"])
        assert ended.value.code == 2
        assert "inside the stored run" in capsys.readouterr().err
        assert not (FIXTURE / inside).exists()
    assert digests(FIXTURE) == before


def test_no_claim_text_is_printed_unless_asked(record: dict[str, Any]) -> None:
    quiet = json.dumps(record) + render_record(record)
    assert not [s for s in CLAIM_SENTENCES if s in quiet]
    assert not any("message" in flag for flag in record["judge"]["flags"])

    shown = replay_run(read_run(FIXTURE), show_text=True)
    static = next(a for a in shown["analysts"]["static"]["answers"] if a["replayed"])
    unknown = next(f for f in static["flags"] if f["code"] == "attck.unknown_id")
    assert "T9999" in unknown["message"]
    assert unknown["claim"].startswith("It registers a scheduled task named Updater")
    assert all("message" in flag for flag in shown["judge"]["flags"])


def test_the_replay_reaches_no_network_and_puts_every_door_back() -> None:
    from maljan.memory import attck_loader

    connect, lookup = socket.create_connection, socket.getaddrinfo
    cache = attck_loader.ATTCK_CACHE_DIR
    with replay_environment({}) as env:
        with pytest.raises(ReplayRefused):
            socket.create_connection(("127.0.0.1", 9))
        with pytest.raises(ReplayRefused):
            socket.getaddrinfo("localhost", 80)
        assert attck_loader.ATTCK_CACHE_DIR == env.cache_dir
        assert env.cache_dir != Path.home() / ".cache" / "maljan" / "attck"
    assert socket.create_connection is connect
    assert socket.getaddrinfo is lookup
    assert attck_loader.ATTCK_CACHE_DIR == cache


def test_two_records_are_told_apart_by_what_moved(record: dict[str, Any]) -> None:
    assert not differs(diff_records(record, copy.deepcopy(record)))

    moved = copy.deepcopy(record)
    answer = next(a for a in moved["analysts"]["static"]["answers"] if a["replayed"])
    answer["flags"] = [f for f in answer["flags"] if f["code"] != "attck.unknown_id"]
    moved["judge"]["flags"].append({"code": "stix.malformed_hash", "path": "objects[9]"})
    moved["report"]["techniques"]["T1105"] = {"published": False, "why": "a reason"}
    moved["report"]["severity"] = "High"
    diff = diff_records(record, moved)

    assert differs(diff)
    assert diff["codes_lost"] == [
        {
            "part": "analyst answer",
            "owner": "static round 1",
            "path": "static.claims[2]",
            "subject": "T9999",
            "code": "attck.unknown_id",
            "count": 1,
        }
    ]
    assert diff["codes_gained"] == [
        {"part": "judge", "path": "objects[9]", "code": "stix.malformed_hash", "count": 1}
    ]
    assert diff["report"]["severity"] == {"a": "Medium", "b": "High"}
    assert diff["report"]["techniques"]["changed"]["T1105"]["b"]["published"] is False
    text = render_diff(diff, "A-ref", "B-ref")
    assert "attck.unknown_id" in text and "stix.malformed_hash" in text


def _seconds(work: Callable[[], object]) -> float:
    """The least of two timed runs of ``work``."""
    best = float("inf")
    for _ in range(2):
        started = time.perf_counter()
        work()
        best = min(best, time.perf_counter() - started)
    return best


def _flagged_answer(n: int) -> tuple[list[Any], Any]:
    """An answer of ``n`` claims, each the subject of one finding."""
    from maljan.pipeline.validation import Violation
    from maljan.schemas.isr_models import AgentISR, ClaimEvidence

    claims = [
        ClaimEvidence(claim=f"claim {i}", evidence_ref=f"[ev_{i + 1:04d}]", confidence=0.5)
        for i in range(n)
    ]
    found = [
        Violation(code="isr.empty_evidence", message="m", path=f"static.claims[{i}]")
        for i in range(n)
    ]
    return found, AgentISR(agent_id="static", domain="static", claims=claims)


def _record_of(n: int, code: str) -> dict[str, Any]:
    flags = [{"code": code, "path": f"static.claims[{i}]"} for i in range(n)]
    return {
        "format": REPLAY_FORMAT,
        "run": "hostile",
        "analysts": {"static": {"answers": [{"answer": "round 1", "flags": flags}]}},
        "report": {
            "techniques": {f"T{1000 + i % 9000}.{i:03d}": {"published": True} for i in range(n)}
        },
    }


def test_the_replay_s_own_bookkeeping_stays_linear() -> None:
    from scripts.replay.rules import _claim_flags

    # Ten times the findings in about ten times the time; a step that looked
    # each finding's claim up by a walk of the claims would be a hundred.
    small, large = _flagged_answer(2_000), _flagged_answer(20_000)
    _claim_flags(*small, show_text=False)
    low = _seconds(lambda: _claim_flags(*small, show_text=True))
    high = _seconds(lambda: _claim_flags(*large, show_text=True))
    assert high < low * 20, (low, high)

    pairs = {n: (_record_of(n, "a.code"), _record_of(n, "b.code")) for n in (2_000, 20_000)}
    diff_records(*pairs[2_000])
    low = _seconds(lambda: diff_records(*pairs[2_000]))
    high = _seconds(lambda: diff_records(*pairs[20_000]))
    assert len(diff_records(*pairs[20_000])["codes_gained"]) == 20_000
    assert high < low * 20, (low, high)


def test_a_job_read_from_the_database_is_written_in_the_stored_layout(tmp_path: Path) -> None:
    job_id = uuid.UUID("00000000-0000-4000-8000-000000000001")
    stamp = datetime(2026, 1, 1, tzinfo=UTC)
    assert jsonable({"id": job_id, "at": stamp, "seconds": Decimal("1.5")}) == {
        "id": str(job_id),
        "at": stamp.isoformat(),
        "seconds": 1.5,
    }
    rows = JobRows(
        job={"id": str(job_id), "sample_sha256": "0" * 64},
        report={
            "id": "r1",
            "agent_reports": {"static": "CLAIM: x"},
            "run_summary": {"settings_snapshot": {}},
            "malware_report": {"verdict": "Benign"},
            "judge_stix_bundle": {"bundle": {"objects": []}, "as_written": True},
        },
        findings=[{"agent_name": "static", "claims": []}],
        transcript=[{"seq": 2, "speaker": "static"}, {"seq": 1, "speaker": "static"}],
        evidence=[{"entry_id": "ev_0002", "seq": 2}, {"entry_id": "ev_0001", "seq": 1}],
        events=[{"seq": 1, "type": "completed", "payload": {}}],
    )
    stored = read_run(write_run(rows, tmp_path / str(job_id)))
    assert [e["entry_id"] for e in stored.evidence] == ["ev_0001", "ev_0002"]
    assert stored.agent_reports == {"static": "CLAIM: x"}
    assert [m["seq"] for m in stored.transcript] == [1, 2]
    assert stored.report == {"verdict": "Benign"}
    assert stored.judge == {"bundle": {"objects": []}, "as_written": True}
    assert stored.job is not None and stored.job["sample_sha256"] == "0" * 64
