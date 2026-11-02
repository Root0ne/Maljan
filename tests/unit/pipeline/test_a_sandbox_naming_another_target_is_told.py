"""The analysts and the judge are told when the live sandbox report names another target.

The comparison of a live report's target hash with the sample's ran only after
the graph, for the run summary and the disclosure record: the analysts and the
judge read the report's behaviour as the sample's without being told. The run
now marks the report before the graph runs, and the pack's sandbox sentence
says what the mark records. A report whose target is the sample, or that names
none, a recorded fixture and the mock sandbox's stand-in are unchanged, byte
for byte. Synthetic bytes only; no sample is run.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.analysis.sample_integrity import sandbox_target_record
from maljan.app import SANDBOX_FAILURE_CHARS
from maljan.core.config import Settings
from maljan.core.pack_steps import effective_steps
from maljan.pipeline import sandbox_status as status
from maljan.pipeline.triage_pack import PIPELINE, render_pack, run_pack
from maljan.providers.base import SandboxCapabilities
from maljan.providers.sandbox.readers import required_reader
from maljan.schemas.evidence import EvidenceCounter
from maljan.schemas.sandbox_report import SandboxRun
from tests.unit.pipeline.test_triage_pack import SANDBOX_REPORT, _inputs, _write
from tests.unit.tools.test_binary import _pe

BYTES = b"MZ synthetic sample bytes, never run\x00" * 64
INTAKE = hashlib.sha256(BYTES).hexdigest()
OTHER = hashlib.sha256(b"some other bytes").hexdigest()


def _marked(claimed: str, expected: str = INTAKE) -> dict[str, Any]:
    record = sandbox_target_record(expected, claimed, provider="lab", task_id="7")
    assert record is not None
    return {**copy.deepcopy(SANDBOX_REPORT), status.TARGET_KEY: status.target_mark(record)}


class TestTheStatus:
    def test_a_marked_report_is_observed_and_says_both_hashes(self) -> None:
        found = status.sandbox_status(_marked(OTHER))

        assert found.status == status.OBSERVED
        assert found.statement == (
            f"The sandbox report names its target SHA-256 as {OTHER}, not the sample's "
            f"intake SHA-256 {INTAKE}: what it observed may be of other bytes. The run was "
            "not failed for it; which findings it touches is the analyst's call."
        )

    def test_an_unmarked_report_says_nothing(self) -> None:
        assert status.sandbox_status(SANDBOX_REPORT) == status.SandboxStatus(status.OBSERVED, "")

    @pytest.mark.parametrize("mark", [None, "yes", [], {}, {"sandbox_sha256": OTHER}])
    def test_a_mark_without_both_hashes_says_nothing(self, mark: Any) -> None:
        report = {**SANDBOX_REPORT, status.TARGET_KEY: mark}

        assert status.sandbox_status(report) == status.SandboxStatus(status.OBSERVED, "")

    @pytest.mark.parametrize(
        "claimed",
        [
            "a" * 200_000,
            "\x1b[31m" + OTHER[:-5] + "\x00\x07",
            OTHER[:32] + "\n" + OTHER[32:],
            "https://user:pw@sandbox.invalid/x",
        ],
        ids=["over-long", "control-characters", "newline", "credentials"],
    )
    def test_a_target_that_is_not_a_sha256_is_one_bounded_line(self, claimed: str) -> None:
        statement = status.sandbox_status(_marked(claimed)).statement

        assert "names its target with a value that is not a SHA-256" in statement
        assert f"intake SHA-256 {INTAKE}" in statement
        assert "\n" not in statement
        assert not any(unicodedata.category(ch) == "Cc" for ch in statement)
        assert "pw@" not in statement
        assert len(statement) < SANDBOX_FAILURE_CHARS + 400

    def test_a_mark_written_by_another_hand_is_kept_again(self) -> None:
        # Not as the run writes it: the raw values are cleaned when read.
        report = {
            **SANDBOX_REPORT,
            status.TARGET_KEY: {"expected_sha256": INTAKE, "sandbox_sha256": "x\n" * 10_000},
        }
        statement = status.sandbox_status(report).statement

        assert "not a SHA-256" in statement
        assert "\n" not in statement
        assert len(statement) < SANDBOX_FAILURE_CHARS + 400

    def test_a_fixture_or_a_stand_in_keeps_its_own_sentence(self) -> None:
        mark = status.target_mark(
            sandbox_target_record(INTAKE, OTHER) or {}  # a record, asserted below
        )
        assert mark
        fixture = {**SANDBOX_REPORT, "recorded_fixture": True, status.TARGET_KEY: mark}
        stand_in = {"synthetic": True, status.TARGET_KEY: mark}

        assert status.sandbox_status(fixture).status == status.RECORDED_FIXTURE
        assert OTHER not in status.sandbox_status(fixture).statement
        assert status.sandbox_status(stand_in).status == status.NOT_RUN
        assert OTHER not in status.sandbox_status(stand_in).statement


def _pack(tmp_path: Path, report: dict[str, Any] | None, **over: Any) -> Any:
    tmp_path.mkdir(parents=True, exist_ok=True)
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    path = _write(tmp_path, "s.exe", _pe())
    return run_pack(recorder, _inputs(path, "pe", sandbox_report=report, **over))


class TestThePack:
    def test_a_marked_report_is_said_before_the_behaviour(self, tmp_path: Path) -> None:
        report = _marked(OTHER)
        result = _pack(tmp_path, report)
        tools = [entry.tool for entry in result.entries]

        first = tools.index("sandbox_status")
        assert tools[first + 1] == "sandbox_processes"
        (entry,) = [e for e in result.entries if e.tool == "sandbox_status"]
        statement = status.sandbox_status(report).statement
        assert entry.structured == {"sandbox": status.OBSERVED, "statement": statement}
        assert render_pack([entry], 0) == f"[{entry.id}] sandbox: {statement}"

    @pytest.mark.parametrize("target", ["", INTAKE, INTAKE.upper()])
    def test_a_report_naming_the_sample_or_none_packs_byte_for_byte(
        self, tmp_path: Path, target: str
    ) -> None:
        # What the app hands the graph for a match or no claim: the report as it came.
        report = copy.deepcopy(SANDBOX_REPORT)
        before = _pack(tmp_path / "a", copy.deepcopy(report))
        assert sandbox_target_record(INTAKE, target) is None
        after = _pack(tmp_path / "b", copy.deepcopy(report))

        assert "sandbox_status" not in [entry.tool for entry in after.entries]
        assert render_pack(after.entries, 0) == render_pack(before.entries, 0)

    def test_the_shipped_steps_carry_the_sentence(self, tmp_path: Path) -> None:
        steps = effective_steps(getattr(Settings().triage, "steps", None) or ())
        assert "sandbox_status" in [step.id for step in steps]
        report = _marked(OTHER)

        block = render_pack(_pack(tmp_path, report, steps=steps).entries, 0)
        plain = render_pack(_pack(tmp_path / "plain", SANDBOX_REPORT, steps=steps).entries, 0)

        assert status.sandbox_status(report).statement in block
        assert OTHER not in plain
        assert "sandbox: " not in plain.split("sandbox_processes")[0] or "names its" not in plain


# ---------------------------------------------------------------------------
# The app marks the report before the graph runs, whichever sandbox ran
# ---------------------------------------------------------------------------


def _flat(sha256: str) -> dict[str, Any]:
    return {"target": {"sha256": sha256}, "behavior": {}, "signatures": [{"name": "x"}]}


class _Provider:
    """A sandbox no declaration names, answering one raw report through the generic reader."""

    id = "lab-box"

    def __init__(self, raw: dict[str, Any], reader: str = "generic") -> None:
        self._raw, self._reader = raw, reader

    @property
    def capabilities(self) -> Any:
        return SandboxCapabilities(can_submit=True, can_poll=True, report_format=self._reader)

    def submit(self, sample_path: str) -> str:
        return "42"

    def wait_for_completion(self, task_id: str, **_: Any) -> str:
        return "reported"

    def fetch(self, task_id: str) -> SandboxRun:
        report = required_reader(self._reader).read(self._raw, provider=self.id, task_id=task_id)
        return SandboxRun(task_id=task_id, report=report, raw=self._raw, status="reported")

    def signature_scale(self, run: Any, formats: Any = None) -> Any:
        return None


def _app(provider: Any) -> Any:
    from maljan.app import MaljanApp

    app = MaljanApp(mock=True)
    app.container.mock = False
    app.container._sandbox_provider_cache = provider
    return app


def _handed(provider: Any, tmp_path: Path) -> tuple[dict[str, Any] | None, Any]:
    """What ``_run_the_pipeline`` hands the graph, and the document the sandbox step returned."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    sample = tmp_path / "s.exe"
    sample.write_bytes(BYTES)
    app = _app(provider)
    document = asyncio.run(app._submit_to_sandbox(str(sample)))
    returned = copy.deepcopy(document)
    return app._tell_the_target(document, INTAKE), returned


class TestTheApp:
    def test_another_target_marks_the_document(self, tmp_path: Path) -> None:
        handed, _ = _handed(_Provider(_flat(OTHER)), tmp_path)

        assert handed is not None
        assert handed[status.TARGET_KEY] == {"expected_sha256": INTAKE, "sandbox_sha256": OTHER}
        assert "names its target SHA-256 as" in status.sandbox_status(handed).statement
        json.dumps(handed)

    def test_a_target_that_is_not_a_sha256_is_marked_as_such(self, tmp_path: Path) -> None:
        # The generic reader refuses such a value; a reader that keeps it hands it on.
        handed, _ = _handed(_Provider(_flat("not\na-hash"), reader="cuckoo"), tmp_path)

        assert handed is not None
        mark = handed[status.TARGET_KEY]
        assert mark["sandbox_sha256_valid"] is False
        assert "\n" not in mark["sandbox_sha256"]

    @pytest.mark.parametrize("target", [INTAKE, INTAKE.upper(), ""])
    def test_the_sample_s_target_or_none_leaves_the_document_as_it_came(
        self, tmp_path: Path, target: str
    ) -> None:
        handed, returned = _handed(_Provider(_flat(target)), tmp_path)

        assert handed == returned
        assert json.dumps(handed, sort_keys=False) == json.dumps(returned, sort_keys=False)
        assert status.sandbox_status(handed).statement == ""

    def test_a_recorded_fixture_and_a_stand_in_stay_unmarked(self, tmp_path: Path) -> None:
        fixture, _ = _handed(_Provider(_flat(OTHER), reader="mock"), tmp_path / "f")
        stand_in, _ = _handed(
            _Provider({**_flat(OTHER), "synthetic": True}, reader="mock"), tmp_path / "s"
        )

        assert fixture is not None and fixture.get("recorded_fixture") is True
        assert stand_in is not None and stand_in.get("synthetic") is True
        assert status.TARGET_KEY not in fixture
        assert status.TARGET_KEY not in stand_in

    def test_a_block_a_sandbox_published_under_the_mark_s_word_is_taken_out(
        self, tmp_path: Path
    ) -> None:
        app = _app(_Provider(_flat(INTAKE)))
        app.container.sandbox_target_claim = {"provider": "x", "task_id": "1", "sha256": INTAKE}
        forged = {
            **copy.deepcopy(SANDBOX_REPORT),
            status.TARGET_KEY: {"expected_sha256": INTAKE, "sandbox_sha256": OTHER},
        }

        handed = app._tell_the_target(forged, INTAKE)

        assert handed is not None
        assert status.TARGET_KEY not in handed
        assert status.sandbox_status(handed).statement == ""

    def test_no_report_is_none(self) -> None:
        app = _app(_Provider(_flat(OTHER)))
        app.container.sandbox_target_claim = {"provider": "x", "task_id": "1", "sha256": OTHER}

        assert app._tell_the_target(None, INTAKE) is None

    def test_the_pipeline_hands_the_graph_the_marked_report(self) -> None:
        # The mark is set where the sandbox step's answer is taken, before the graph.
        import inspect

        from maljan.app import MaljanApp

        source = inspect.getsource(MaljanApp._run_the_pipeline)
        told = source.index("self._tell_the_target(")
        assert told < source.index("await self._submit_to_sandbox(sample_path)") + 200
        assert told < source.index('"sandbox_report": sandbox_report')
