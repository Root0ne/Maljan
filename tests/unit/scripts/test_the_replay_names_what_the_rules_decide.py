"""The replay re-runs the platform's deterministic rules over a stored run, and only reads it.

A tiny stored run (``tests/fixtures/replay/tiny``) is replayed in this process
and each producer's codes are the ones its answers raise under today's rules:
the analysts' answers and claims in force, the judge's bundle, the narrative,
a composer section, a tool call and the report linter. The claims in force
carry notes the run decided (a technique id marked not valid, an absence claim
not yet noted); the replay resets them and decides them again, so a change to
a check reaches what the report publishes, and a test changes one check and
sees a technique and an indicator move. The replay is the same twice, leaves
every file of the run as it was, reaches no network, prints no claim text
unless asked, names what it could not replay, and ends with status 2 when a
part raised. Two records of one run are told apart by every code they gained
or lost and every report value that moved.
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
from scripts.replay.compare import diff_records, differs, has_errors
from scripts.replay.database import JobRows, jsonable, with_sample, write_run
from scripts.replay.guard import ReplayRefused, replay_environment
from scripts.replay.output import render_diff, render_record
from scripts.replay.record import REPLAY_SCHEMA, errors
from scripts.replay.rules import replay_run
from scripts.replay.stored import (
    StoredRun,
    StoredRunChanged,
    check_unchanged,
    digests,
    read_run,
)

from maljan.pipeline import validation
from tests.unit.scripts._replay_tiny import EXPECTED_TOTALS, FIXTURE

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
    assert record["schema"] == REPLAY_SCHEMA
    assert record["totals"] == EXPECTED_TOTALS
    assert errors(record) == []

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
        },
        {
            "code": "attck.absence_claim",
            "path": "static.claims[3]",
            "subject": "T1055",
            "entries": ["ev_0002"],
        },
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
    assert published == {"T1027": True, "T1055": True, "T1105": True, "T9998": False}
    assert report["export"]["attack_patterns"] == ["T1027", "T1055", "T1105"]
    assert report["claims_not_discussed"] == {"static": [3, 4]}
    assert report["detection_rules"] == {"yara": 1}


def test_the_stored_claim_notes_are_decided_again(record: dict[str, Any]) -> None:
    # The run stored T1105's id as not valid and T1055's absence claim as not
    # kept when asked; neither is taken from the record.
    in_force = record["analysts"]["static"]["in_force"]
    assert in_force["not_valid"] == []
    assert in_force["kept_after_absence_question"] == ["T1055"]
    assert record["report"]["techniques"]["T1105"] == {"published": True}
    named = {row["part"]: row["why"] for row in record["not_replayed"]}
    assert "run summary" in named and "rebuilt from the replayed findings" in named["run summary"]


def test_a_validator_change_moves_what_is_published(
    record: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    known = validation._technique_is_known
    monkeypatch.setattr(
        validation,
        "_technique_is_known",
        lambda tid, attck: tid != "T1105" and known(tid, attck),
    )
    stricter = replay_run(read_run(FIXTURE))
    monkeypatch.undo()
    monkeypatch.setattr(validation, "_indicator_problem", lambda *_a, **_k: "")
    looser = replay_run(read_run(FIXTURE))

    technique = diff_records(record, stricter)
    assert technique["report"]["techniques"]["changed"]["T1105"]["b"]["published"] is False
    assert technique["report"]["exported_techniques"] == {"only_a": ["T1105"], "only_b": []}
    assert stricter["analysts"]["static"]["in_force"]["not_valid"] == ["T1105"]

    indicator = diff_records(record, looser)
    assert indicator["codes_lost"] == [
        {
            "part": "judge",
            "path": "objects[3] 'indicator--1'",
            "code": "stix.ungrounded_indicator",
            "count": 1,
        }
    ]
    assert list(indicator["report"]["indicators"]["only_b"]) == ["domain:2d5a0519f25d"]
    assert looser["judge"]["indicators_dropped"] == 0


def test_what_the_stored_run_cannot_give_is_named(record: dict[str, Any]) -> None:
    named = {(row["part"], row["why"]) for row in record["not_replayed"]}
    assert ("analyst network round 1", "stored truncated at 111 characters") in named
    assert (
        "analyst static round 0",
        "stored as the platform's summary of its claims, not as the analyst wrote it",
    ) in named
    parts = {part for part, _why in named}
    assert {"analysts", "judge", "composer", "judge evidence", "report", "run summary"} <= parts
    whys = " ".join(why for _part, why in named)
    for named_input in ("isr.retry_dropped", "nudge", "degraded_mode", "shown"):
        assert named_input in whys
    network = record["analysts"]["network"]["answers"]
    assert [(a["answer"], a["replayed"]) for a in network] == [
        ("round 0", False),
        ("round 1", False),
        ("round 2", True),
    ]


def test_a_part_that_raises_is_an_error_and_the_command_says_so(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def _raise(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("a check that breaks")

    monkeypatch.setattr(validation, "parse_violations", _raise)
    broken = replay_run(read_run(FIXTURE))
    raised = errors(broken)
    assert [row["part"] for row in raised] == ["analyst static answers", "analyst network answers"]
    assert all(row["why"].startswith("RuntimeError at ") for row in raised)
    assert "ERROR: analyst static answers raised" in render_record(broken)

    out = tmp_path / "broken.json"
    assert replay_cli.main([str(FIXTURE), "--json", str(out), "--quiet"]) == 2
    assert "raised: RuntimeError" in capsys.readouterr().err

    monkeypatch.undo()
    whole = replay_run(read_run(FIXTURE))
    diff = diff_records(broken, whole)
    assert has_errors(diff)
    same = diff_records(broken, copy.deepcopy(broken))
    assert has_errors(same) and not differs(same)
    text = render_diff(same, "A-ref", "B-ref")
    assert "ERROR under A" in text and "no difference" not in text


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
    for flag, inside in (("--json", "record.json"), ("--work", "trees"), ("--job-dir", "jobs")):
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

    connect, lookup, by_name = socket.create_connection, socket.getaddrinfo, socket.gethostbyname
    cache = attck_loader.ATTCK_CACHE_DIR
    with replay_environment({}) as env:
        with pytest.raises(ReplayRefused):
            socket.create_connection(("127.0.0.1", 9))
        with pytest.raises(ReplayRefused):
            socket.getaddrinfo("localhost", 80)
        with pytest.raises(ReplayRefused):
            socket.gethostbyname("localhost")
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram,
            pytest.raises(ReplayRefused),
        ):
            datagram.sendto(b"x", ("127.0.0.1", 9))
        assert attck_loader.ATTCK_CACHE_DIR == env.cache_dir
        assert env.cache_dir != Path.home() / ".cache" / "maljan" / "attck"
    assert socket.create_connection is connect
    assert socket.getaddrinfo is lookup
    assert socket.gethostbyname is by_name
    assert "sendto" not in vars(socket.socket)
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

    assert differs(diff) and not has_errors(diff)
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


def test_records_of_two_schemas_are_compared_on_what_both_define(record: dict[str, Any]) -> None:
    older = copy.deepcopy(record)
    del older["schema"]
    older["format"] = 1
    for agent in older["analysts"].values():
        for key in ("not_valid", "kept_after_absence_question"):
            agent.get("in_force", {}).pop(key, None)
    del older["report"]["degraded"]
    diff = diff_records(older, record)
    assert diff["schema"] == {"a": 1, "b": REPLAY_SCHEMA}
    assert not differs(diff)
    assert "only what both define is compared" in render_diff(diff, "A-ref", "B-ref")


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
        "schema": REPLAY_SCHEMA,
        "run": "hostile",
        "analysts": {"static": {"answers": [{"answer": "round 1", "flags": flags}]}},
        "report": {
            "techniques": {f"T{1000 + i % 9000}.{i:03d}": {"published": True} for i in range(n)}
        },
    }


def _summaries_of(agents: int) -> StoredRun:
    """A stored run of ``agents`` analysts, each with ten messages the replay names and skips."""
    transcript = [
        {
            "speaker": f"agent{a}",
            "role": "analyst" if m == 0 else "reviser",
            "round": m,
            "report": "CLAIM 1: x" if m == 0 else "",
            "claims": [{"claim": "x"}] if m == 0 else [],
        }
        for a in range(agents)
        for m in range(10)
    ]
    reports = {f"agent{a}": "" for a in range(agents)}
    return StoredRun(
        name="hostile",
        root=FIXTURE,
        byjob={"agent_reports": reports, "transcript": transcript},
    )


def test_the_replay_s_own_bookkeeping_stays_linear() -> None:
    from scripts.replay.rules import _analysts, _claim_flags, _Run

    # Ten times the input in about ten times the time; a step that walked the
    # whole of it for each of its items would be a hundred.
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

    def _name(n: int) -> None:
        run = _Run(stored=StoredRun(name="hostile", root=FIXTURE), show_text=False)
        for i in range(n):
            run.name("part", f"why {i}")
        assert len(run.not_replayed) == n

    low = _seconds(lambda: _name(2_000))
    high = _seconds(lambda: _name(20_000))
    assert high < low * 20, (low, high)

    stores = {n: _summaries_of(n) for n in (200, 2_000)}
    _analysts(_Run(stored=stores[200], show_text=False))
    low = _seconds(lambda: _analysts(_Run(stored=stores[200], show_text=False)))
    high = _seconds(lambda: _analysts(_Run(stored=stores[2_000], show_text=False)))
    assert len(_analysts(_Run(stored=stores[2_000], show_text=False))) == 2_000
    assert high < low * 20, (low, high)


def test_a_job_read_from_the_database_is_written_in_the_stored_layout(tmp_path: Path) -> None:
    job_id = uuid.UUID("00000000-0000-4000-8000-000000000001")
    stamp = datetime(2026, 1, 1, tzinfo=UTC)
    assert jsonable({"id": job_id, "at": stamp, "seconds": Decimal("1.5")}) == {
        "id": str(job_id),
        "at": stamp.isoformat(),
        "seconds": 1.5,
    }
    job = with_sample(
        {"id": str(job_id), "sample_id": "s1"}, {"sha256": "0" * 64, "original_filename": "x.bin"}
    )
    assert (job["sample_sha256"], job["sample_filename"]) == ("0" * 64, "x.bin")
    gone = with_sample({"id": str(job_id)}, None)
    assert (gone["sample_sha256"], gone["sample_row"]) == (None, "absent")

    rows = JobRows(
        job=job,
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
    target = tmp_path / str(job_id)
    written, cleared = write_run(rows, target)
    assert cleared == []
    stored = read_run(written)
    assert [e["entry_id"] for e in stored.evidence] == ["ev_0001", "ev_0002"]
    assert stored.agent_reports == {"static": "CLAIM: x"}
    assert [m["seq"] for m in stored.transcript] == [1, 2]
    assert stored.report == {"verdict": "Benign"}
    assert stored.judge == {"bundle": {"objects": []}, "as_written": True}
    assert stored.job is not None and stored.job["sample_sha256"] == "0" * 64

    # A second export of a job with no judge answer clears the first one's,
    # and leaves a file of the operator's own alone.
    (target / "notes.txt").write_text("mine", encoding="utf-8")
    rows.report = {**(rows.report or {}), "judge_stix_bundle": None}
    _written, cleared = write_run(rows, target)
    assert "stix-judge.json" in cleared
    assert not (target / "stix-judge.json").exists()
    assert (target / "notes.txt").read_text(encoding="utf-8") == "mine"
