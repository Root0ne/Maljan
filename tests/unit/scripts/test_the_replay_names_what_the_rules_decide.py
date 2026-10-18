"""The replay re-runs the platform's deterministic rules over a stored run, and only reads it.

A tiny stored run (``tests/fixtures/replay/tiny``) is replayed in this process
and each producer's codes are the ones its answers raise under today's rules:
the analysts' answers and claims in force, the judge's bundle, the narrative,
a composer section, a tool call and the report linter. The claims in force
carry notes the run decided (a technique id marked not valid, an absence claim
not yet noted); the replay resets them and decides them again, so a change to
a check reaches what the report publishes, and a test changes one check and
sees a technique and an indicator move. The stored degradation reasons the
verdict decides are decided again, and a finding the stored summary says its
producer was not shown leaves no note. The replay is the same twice, leaves
every file of the run as it was, reaches no network, carries no value from the
run unless asked for the text, names what it could not replay, says what the
rebuilt report does not share with the stored one, and ends with status 2 when
a part raised. Two records of one run are told apart by every code they gained
or lost and every report value that moved, and two of different schemas make a
partial comparison.
"""

from __future__ import annotations

import copy
import json
import os
import re
import shutil
import socket
import time
import uuid
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from scripts.replay import compare
from scripts.replay import rules as replay_rules
from scripts.replay import run as replay_cli
from scripts.replay.compare import diff_records, differs, has_errors, is_partial
from scripts.replay.database import JobRows, jsonable, with_sample, write_run
from scripts.replay.guard import ReplayRefused, replay_environment
from scripts.replay.output import render_diff, render_record
from scripts.replay.record import REPLAY_SCHEMA, digest, errors, value_free_subject
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
# A literal quoted in a STIX pattern.
_QUOTED = re.compile(r"'((?:[^'\\]|\\.)+)'")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


@pytest.fixture(scope="module")
def record() -> dict[str, Any]:
    return replay_run(read_run(FIXTURE))


def _flags(entry: dict[str, Any]) -> list[dict[str, Any]]:
    return [{k: v for k, v in flag.items() if k != "message"} for flag in entry["flags"]]


def _copy_run(tmp_path: Path, **edits: Callable[[dict[str, Any]], None]) -> Path:
    """The tiny run copied, with each named file's JSON edited (``report_json=...``)."""
    target = tmp_path / "tiny"
    shutil.copytree(FIXTURE, target)
    for name, edit in edits.items():
        path = target / name.replace("_json", ".json").replace("_", "-")
        data = json.loads(path.read_text(encoding="utf-8"))
        edit(data)
        path.write_text(json.dumps(data), encoding="utf-8")
    return target


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
    assert report["category"] == f"sha256:{digest('loader')}"
    published = {tid: row["published"] for tid, row in report["techniques"].items()}
    assert published == {"T1027": True, "T1055": True, "T1105": True, "T9998": False}
    assert report["export"]["attack_patterns"] == ["T1027", "T1055", "T1105"]
    # The narrative breaks its schema under these rules: the round would keep none, and the
    # deterministic summary discusses none of the claims in force.
    assert record["narrative"]["kept"] is False
    assert report["claims_not_discussed"] == {"network": [1], "static": [1, 2, 3, 4]}
    assert report["detection_rules"] == {"suricata": 1, "yara": 1}
    # The URL the decoder recovered, its host and the sample's own digest, by
    # kind and digest, each answer by its head and a digest of its words.
    assert {key.split(":")[0]: row["published"] for key, row in report["indicators"].items()} == {
        "domain": "yes",
        "hash": "yes",
        "url": "yes",
    }
    assert all(set(row) == {"kind", "published", "answer"} for row in report["indicators"].values())
    assert report["degraded"] is True
    assert report["degradation"] == {"decided": 0, "stored_decided_again": 0, "kept_as_stored": 2}


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
    assert indicator["judge"] == {"indicators_dropped": {"a": 1, "b": 0}}


def test_what_the_stored_run_cannot_give_is_named(record: dict[str, Any]) -> None:
    named = {(row["part"], row["why"]) for row in record["not_replayed"]}
    assert ("analyst network round 1", "stored truncated at 111 characters") in named
    assert (
        "analyst static round 0",
        "stored as the platform's summary of its claims, not as the analyst wrote it",
    ) in named
    parts = {part for part, _why in named}
    assert {
        "analysts",
        "judge",
        "composer",
        "judge evidence",
        "ledger",
        "identity",
        "report",
        "run summary",
    } <= parts
    whys = " ".join(why for _part, why in named)
    for named_input in (
        "isr.retry_dropped",
        "nudge",
        "byte budget",
        "keeps no key order",
        "routed file type",
        "shown",
        "agent_stats",
    ):
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
    for timeout in ("0", "-1"):
        with pytest.raises(SystemExit) as ended:
            replay_cli.main([str(FIXTURE), "--compare", "A", "B", "--timeout", timeout])
        assert ended.value.code == 2
        assert "--timeout takes a number of seconds above 0" in capsys.readouterr().err
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
    assert shown["report"]["category_text"] == "loader"


def _strings(value: Any) -> Iterator[str]:
    """Every key and every text of a record, nested ones included."""
    if isinstance(value, dict):
        for key, inner in value.items():
            yield str(key)
            yield from _strings(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from _strings(inner)
    elif value is not None:
        yield str(value)


def _values_of(run: Path, shown: dict[str, Any]) -> set[str]:
    """Every indicator value the run holds: its IOC table's, the stored report's and the judge's."""
    values = {str(row["value"]) for row in shown["report"]["indicators"].values()}
    stored = run / "report.json"
    if stored.is_file():
        report = json.loads(stored.read_text(encoding="utf-8"))
        values.update(
            str(row.get("value"))
            for row in report.get("consolidated_iocs") or []
            if isinstance(row, dict) and row.get("value")
        )
    judge = run / "stix-judge.json"
    if judge.is_file():
        for obj in json.loads(judge.read_text(encoding="utf-8"))["bundle"].get("objects") or []:
            if obj.get("type") == "indicator":
                values.update(_QUOTED.findall(str(obj.get("pattern") or "")))
        for obj in json.loads(judge.read_text(encoding="utf-8"))["bundle"].get("objects") or []:
            # The judge's own names for its objects, and the id parts that are not a
            # number or a UUID: a path quotes the label.
            if obj.get("type") == "malware" and obj.get("name"):
                values.add(str(obj["name"]))
            ident = str(obj.get("id") or "")
            rest = ident.partition("--")[2]
            if rest and not rest.isdigit() and not _UUID.match(rest):
                values.add(ident)
    for flag in _all_flags(shown):
        if flag.get("subject_text"):
            values.add(str(flag["subject_text"]).partition(":")[2] or str(flag["subject_text"]))
    return {value for value in values if len(value) >= 4}


def _all_flags(record: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for agent in record["analysts"].values():
        for answer in agent["answers"]:
            yield from answer.get("flags") or []
        yield from (agent.get("in_force") or {}).get("flags") or []
    for part in ("judge", "narrative", "tool", "fp_linter"):
        yield from (record.get(part) or {}).get("flags") or []
    for section in (record.get("composer") or {}).get("sections", {}).values():
        yield from section.get("flags") or []


def test_no_value_of_the_run_is_in_the_record_without_the_text() -> None:
    runs = [FIXTURE]
    extra = os.environ.get("MALJAN_REPLAY_RUN")
    if extra:
        runs.append(Path(extra))
    for run in runs:
        shown = replay_run(read_run(run), show_text=True)
        quiet = replay_run(read_run(run))
        values = _values_of(run, shown)
        texts = [text.lower() for text in [*_strings(quiet), render_record(quiet)]]
        assert values, run
        leaked = sorted(v for v in values if any(v.lower() in text for text in texts))
        assert leaked == [], run
        # The same value-free fields either way: the text only adds fields.
        assert {k: v for k, v in shown["report"].items() if not k.endswith("_text")}.keys() == (
            quiet["report"].keys()
        )
    # The tiny run's IOC answers quote a value, so the scan has one to find.
    shown = replay_run(read_run(FIXTURE), show_text=True)
    answers = [str(row.get("answer_text") or "") for row in shown["report"]["indicators"].values()]
    assert any("https://cdn.stage-two-host.net/live/" in answer for answer in answers)
    # And a finding's path quotes a judge's label that names its object.
    paths = [str(flag.get("path_text") or "") for flag in shown["judge"]["flags"]]
    assert any("attack-pattern--fake" in path for path in paths)


def test_a_subject_and_its_path_carry_no_value() -> None:
    from scripts.replay.compare import _failure_named
    from scripts.replay.rules import _flag

    from maljan.pipeline.validation import Violation

    finding = Violation(
        code="stix.indicator_unattributed_flow",
        message="the indicator names host.example.net",
        path="objects.domain:host.example.net",
        subject="domain:host.example.net",
    )
    quiet = _flag(finding, show_text=False)
    assert quiet["subject"] == f"domain:{digest('host.example.net')}"
    assert quiet["path"] == f"objects.domain:{digest('host.example.net')}"
    assert "host.example.net" not in json.dumps(quiet)
    shown = _flag(finding, show_text=True)
    assert shown["subject"] == quiet["subject"]
    assert shown["subject_text"] == "domain:host.example.net"
    assert shown["path_text"] == "objects.domain:host.example.net"

    # The judge's own label for an object, whatever the subject's case.
    family = Violation(
        code="stix.is_family_missing",
        message="m",
        path="objects[0] 'malware--some-family'",
        subject="Some-Family",
    )
    named = _flag(family, show_text=False)
    assert named["path"] == f"objects[0] 'malware--{digest('some-family')}'"
    assert "some-family" not in json.dumps(named).lower()
    plain = _flag(
        Violation(code="c", message="m", path="objects[3] 'indicator--1'"), show_text=False
    )
    assert plain["path"] == "objects[3] 'indicator--1'"

    # An id stays as it is; a value does not pass for its shape.
    for kept in ("T1055.001", "t1055", "ev_0003"):
        assert value_free_subject(kept) == kept
    from maljan.analysis.sandbox_sections import is_item_id

    assert value_free_subject("proc:84", is_item_id) == "proc:84"
    assert value_free_subject("port:4444", is_item_id) == f"port:{digest('4444')}"
    assert value_free_subject("0123456789ab") == f"sha256:{digest('0123456789ab')}"
    assert value_free_subject("domain:0123456789ab") == f"domain:{digest('0123456789ab')}"
    assert value_free_subject("Some Family") == f"sha256:{digest('Some Family')}"

    # A harness that crashed is named by its failure's class and place, never its message.
    said = b"Traceback\nreplay failed: KeyError at rules.py:12 (_judge)\n"
    assert _failure_named(said, 2) == "replay failed: KeyError at rules.py:12 (_judge)"
    older = b"replay failed: ValueError: host.example.net is not a host\n"
    assert _failure_named(older, 2) == "replay failed: ValueError"
    assert _failure_named(b"Segmentation fault\n", 139) == "exit status 139"


def test_a_cell_keeps_its_key_value_pairs_and_merged_rows_carry_the_key_order() -> None:
    from scripts.replay.rules import _row_key, _Run, _section_content

    assert _row_key(["malicious=52, suspicious=0"]) != _row_key(["malicious=0, suspicious=52"])
    assert _row_key(["outer=b=2, c=3"]) == _row_key(["outer=c=3, b=2"])
    assert _row_key(["a=1, b=2, c=3\u2026"]) != _row_key(["c=3, a=1, b=2\u2026"])
    assert _row_key(["a=1, b\u2026"], loose=True) == _row_key(["c=3, a\u2026"], loose=True)

    run = _Run(stored=read_run(FIXTURE), show_text=False)
    run.name("ledger", replay_rules._NO_KEY_ORDER)
    cut_one, cut_two = ["data", "a=1, b=2, c\u2026"], ["data", "c=3, a=1, b\u2026"]
    stored = {"key": "tool_x", "rows": [cut_one, ["k", "v"], cut_two]}
    replayed = {"key": "tool_x", "rows": [cut_one, ["k", "v"]]}
    rows = _section_content(run, "tool_x", stored, replayed)
    assert rows == [
        {
            "section": "tool_x",
            "field": "rows",
            "merged": 1,
            "cause": {"part": "ledger", "why": replay_rules._NO_KEY_ORDER},
        }
    ]
    swapped = {"key": "tool_x", "rows": [["malicious=0, suspicious=52"]]}
    differ = _section_content(
        run, "tool_x", {"key": "tool_x", "rows": [["malicious=52, suspicious=0"]]}, swapped
    )
    assert [r.get("row") for r in differ] == [0, 0] and all("cause" not in r for r in differ)


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

    assert differs(diff) and not has_errors(diff) and not is_partial(diff)
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


def test_the_judge_s_drops_and_each_tree_s_refusals_are_compared(record: dict[str, Any]) -> None:
    moved = copy.deepcopy(record)
    moved["judge"]["indicators_dropped"] = 0
    moved["environment"]["settings_refused"] = {
        "validation.weak_alignment": "refused by this tree's settings model"
    }
    moved["environment"]["doors_this_tree_lacks"] = ["attck_index.load_all_domains"]
    diff = diff_records(record, moved)
    assert diff["judge"] == {"indicators_dropped": {"a": 1, "b": 0}}
    assert diff["environment"] == {
        "settings_refused": {
            "only_b": {"validation.weak_alignment": "refused by this tree's settings model"}
        },
        "doors_this_tree_lacks": {"only_a": [], "only_b": ["attck_index.load_all_domains"]},
    }
    assert differs(diff) and not is_partial(diff)
    text = render_diff(diff, "A-ref", "B-ref")
    assert "indicators_dropped" in text and "validation.weak_alignment" in text


def _older(record: dict[str, Any]) -> dict[str, Any]:
    """The record as a schema-1 harness wrote it: no schema, no notes, no degradation."""
    older = copy.deepcopy(record)
    del older["schema"]
    older["format"] = 1
    for agent in older["analysts"].values():
        for key in ("not_valid", "kept_after_absence_question"):
            agent.get("in_force", {}).pop(key, None)
    del older["report"]["degraded"]
    del older["report"]["degradation"]
    del older["against_stored"]
    return older


def test_two_schemas_make_a_partial_comparison(record: dict[str, Any]) -> None:
    diff = diff_records(_older(record), record)
    assert diff["schema"] == {"a": 1, "b": REPLAY_SCHEMA}
    assert diff["not_compared"] == {
        "b": [
            "claims in force: kept_after_absence_question",
            "claims in force: not_valid",
            "report.degradation",
            "report.degraded",
        ],
        "differently": ["report.techniques: why"],
    }
    assert is_partial(diff) and not differs(diff)
    text = render_diff(diff, "A-ref", "B-ref")
    assert "PARTIAL COMPARISON" in text
    assert "not compared, defined only under B (B-ref): claims in force" in text
    assert "no difference" not in text


def test_a_partial_comparison_ends_with_status_2(
    record: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    older = _older(record)
    monkeypatch.setattr(compare, "materialise", lambda _repo, _ref, into: into)
    monkeypatch.setattr(
        compare,
        "replay_under",
        lambda _tree, _runs, out, **_kwargs: [older if out.name.startswith("a-") else record],
    )
    argv = [str(FIXTURE), "--compare", "A-ref", "B-ref", "--repo", str(tmp_path)]
    assert replay_cli.main([*argv, "--work", str(tmp_path / "work")]) == 2
    printed = capsys.readouterr().out
    assert "PARTIAL COMPARISON" in printed and "no difference" not in printed


def test_a_section_one_tree_alone_composes_is_not_compared(
    record: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    lacking = copy.deepcopy(record)
    sections = lacking["composer"]["sections"]
    quiet_section = next(name for name, entry in sections.items() if not entry["flags"])
    del sections[quiet_section]
    diff = diff_records(record, lacking)
    assert diff["not_compared"] == {"a": [f"composer section: {quiet_section}"]}
    assert is_partial(diff) and not differs(diff)

    moved = copy.deepcopy(record)
    moved["tool"]["calls"] += 1
    moved["composer"]["not_written"] = moved["composer"]["not_written"][1:]
    moved["environment"]["settings_from_run"] = []
    diff = diff_records(record, moved)
    assert diff["tool"] == {
        "calls": {"a": record["tool"]["calls"], "b": record["tool"]["calls"] + 1}
    }
    assert diff["composer"]["not_written"]["only_a"] == record["composer"]["not_written"][:1]
    assert diff["environment"]["settings_from_run"]["only_b"] == []

    monkeypatch.setattr(compare, "materialise", lambda _repo, _ref, into: into)
    monkeypatch.setattr(
        compare,
        "replay_under",
        lambda _tree, _runs, out, **_kwargs: [record if out.name.startswith("a-") else lacking],
    )
    argv = [str(FIXTURE), "--compare", "A-ref", "B-ref", "--repo", str(tmp_path)]
    assert replay_cli.main([*argv, "--work", str(tmp_path / "work")]) == 2
    printed = capsys.readouterr().out
    assert "PARTIAL COMPARISON" in printed and quiet_section in printed


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


def _unshown_run(n: int) -> Any:
    """A run whose summary records ``n`` findings the judge was never shown."""
    from scripts.replay.rules import _Run

    rows = [
        {"agent": "judge", "code": "stix.x", "subject": f"s{i}", "message": "m", "asked": "false"}
        for i in range(n)
    ]
    stored = StoredRun(
        name="hostile", root=FIXTURE, run_summary={"validation": {"unresolved": rows}}
    )
    return _Run(stored=stored, show_text=False)


def test_the_replay_s_own_bookkeeping_stays_linear() -> None:
    from scripts.replay.rules import _analysts, _claim_flags, _Run, _shown_to

    from maljan.pipeline.validation import Violation

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

    found = {
        n: [
            Violation(code="stix.x", message="m", subject=f"s{i}" if i % 2 else f"t{i}")
            for i in range(n)
        ]
        for n in (500, 5_000)
    }
    _shown_to(_unshown_run(500), "judge", found[500])
    low = _seconds(lambda: _shown_to(_unshown_run(500), "judge", found[500]))
    high = _seconds(lambda: _shown_to(_unshown_run(5_000), "judge", found[5_000]))
    assert len(_shown_to(_unshown_run(5_000), "judge", found[5_000])) == 2_500
    assert high < low * 20, (low, high)


def test_stored_degradation_reasons_are_decided_again_or_named(tmp_path: Path) -> None:
    from maljan.agents.judge_agent import VERDICT_FALLBACK_REASON
    from maljan.pipeline.outcome import unrecognised_verdict_reason

    unreadable = unrecognised_verdict_reason(
        SimpleNamespace(x_maljan_assessment=SimpleNamespace(verdict="Maybe"))
    )

    def _decided(report: dict[str, Any]) -> None:
        report["degradation_reasons"] = [VERDICT_FALLBACK_REASON, unreadable]
        report["degraded_mode"] = True

    # Neither reason is one these rules give over the tiny run: both go, and
    # the run is no longer degraded.
    decided = replay_run(read_run(_copy_run(tmp_path / "decided", report_json=_decided)))
    assert decided["report"]["degraded"] is False
    assert decided["report"]["degradation"] == {
        "decided": 0,
        "stored_decided_again": 2,
        "kept_as_stored": 0,
    }

    def _kept(report: dict[str, Any]) -> None:
        report["degradation_reasons"] = ["analyst failures: network"]
        report["degraded_mode"] = True

    kept = replay_run(read_run(_copy_run(tmp_path / "kept", report_json=_kept)))
    assert kept["report"]["degraded"] is True
    assert kept["report"]["degradation"]["kept_as_stored"] == 1
    assert any(
        row["part"] == "report" and row["why"].startswith("1 stored degradation reason(s) are kept")
        for row in kept["not_replayed"]
    )


def test_a_finding_the_analyst_was_not_shown_leaves_no_absence_note(tmp_path: Path) -> None:
    def _unshown(summary: dict[str, Any]) -> None:
        summary["validation"] = {
            "unresolved": [
                {
                    "agent": "static",
                    "code": "attck.absence_claim",
                    "subject": "T1055",
                    "message": "an absence claim never put to the analyst",
                    "asked": "false",
                }
            ]
        }

    replayed = replay_run(read_run(_copy_run(tmp_path, run_summary_json=_unshown)))
    in_force = replayed["analysts"]["static"]["in_force"]
    assert in_force["kept_after_absence_question"] == []
    absence = next(f for f in in_force["flags"] if f["code"] == "attck.absence_claim")
    assert absence["asked"] is False
    describe = next(f for f in in_force["flags"] if f["code"] == "attck.claim_does_not_describe")
    assert "asked" not in describe


def test_the_analysts_are_taken_in_the_order_the_run_held_them(tmp_path: Path) -> None:
    def _held(summary: dict[str, Any]) -> None:
        summary["agent_stats"] = [{"agent_id": "network"}, {"agent_id": "static"}]

    replayed = replay_run(read_run(_copy_run(tmp_path, run_summary_json=_held)))
    assert list(replayed["analysts"]) == ["network", "static"]
    assert not [row for row in replayed["not_replayed"] if "agent_stats" in row["why"]]


def test_the_record_says_what_differs_from_the_stored_report(
    record: dict[str, Any], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    block = record["against_stored"]
    assert block["compared"] is True
    assert block["not_compared"] == [
        "severity",
        "confidence",
        "category",
        "techniques",
        "indicators",
        "export",
    ]
    assert [row["section"] for row in block["sections"]["only_replayed"]] == [
        "identity",
        "tool_pe_info",
        "tool_strings",
        "tool_pcap_summary",
        "tool_decode_string_blobs",
        "tool_decode_string_blobs_results",
    ]
    # The stored Findings table says T1055 was not published; these rules publish it.
    rows = block["sections"]["contents"]
    assert [(r["section"], r["field"], r["row"]) for r in rows] == [
        ("findings", "rows", 1),
        ("findings", "rows", 1),
    ]
    assert all("cause" not in r and "text" not in (r["stored"] or r["replayed"]) for r in rows)

    # The stored report as the rebuilt one, two sections swapped and one row
    # written in another order, and an export with the sandbox's processes.
    seen: dict[str, Any] = {}
    against = replay_rules._against_stored

    def _capture(run: Any, built: Any, values: Any) -> Any:
        seen["sections"] = [s.model_dump(mode="json") for s in built.report.sections]
        return against(run, built, values)

    monkeypatch.setattr(replay_rules, "_against_stored", _capture)
    replay_run(read_run(FIXTURE))
    sections = copy.deepcopy(seen["sections"])
    sections[1], sections[2] = sections[2], sections[1]
    table = next(s for s in sections if len(s.get("rows") or []) > 1)
    table["rows"] = list(reversed(table["rows"]))

    def _stored(report: dict[str, Any]) -> None:
        report["sections"] = sections
        report["dynamic"] = {"process_tree": [{"pid": 1}, {"pid": 2}]}
        report["stix_bundle_extended"] = {
            "objects": [
                {"type": "process", "id": "process--1"},
                {"type": "process", "id": "process--2"},
            ]
        }

    replayed = replay_run(read_run(_copy_run(tmp_path, report_json=_stored)))
    block = replayed["against_stored"]
    moved = [row["section"] for row in block["sections"]["moved"]]
    assert moved == [seen["sections"][2]["key"], seen["sections"][1]["key"]]
    reordered = [r for r in block["sections"]["contents"] if "reordered" in r]
    assert [(r["section"], r["field"]) for r in reordered] == [(table["key"], "rows")]
    assert reordered[0]["cause"]["part"] == "ledger"
    process = next(row for row in block["export"] if row["type"] == "process")
    assert (process["stored"], process["replayed"]) == (2, 0)
    assert process["cause"]["why"].startswith("the sandbox report is not in the stored record")
    text = render_record(replayed)
    assert "Against the stored report" in text and "export process objects: stored 2" in text


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
