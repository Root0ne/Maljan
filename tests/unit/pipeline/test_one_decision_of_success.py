"""Whether a call succeeded is decided once, and every reader reads that.

A tool that *raises* is a failure the caller knows about; a tool that *returns*
``{"error": {"code": …}}`` is a failure only ``build_entry`` knows about — it
is the one place that reads a returned error and turns it into ``ok: false``.
The recorder published its event from the ``ok`` it was *handed* instead, which
for a returned error is always ``True``, so a live run put a green tick and the
word "succeeded" beside six calls whose ledger rows said they had failed and
whose payload was an error object. A reader of the conversation could not see
that anything had gone wrong, and the evidence tab said it had.

The four shapes a tool answer comes in are all driven here, because the
decision has to be the same one for all of them.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import StructuredTool

from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
from maljan.schemas.evidence import EvidenceCounter

# What the analysis sidecar answers with when a path argument names nothing:
# the shape ``maljan.tools.errors`` authors, remediation and all.
STRUCTURED_ERROR = {
    "error": {
        "code": "no_such_file",
        "message": "no such file: /srv/staging/carved/abcdef/body_0x364000",
        "remediation": "pass the path value carve_payloads returned",
    },
    "tool": "identify_file",
}

# What a server outside this project answers with.
FLAT_ERROR = {"error": "the upstream service refused the request"}

# What a tool answers when an optional library is missing: fewer facts, and a
# note saying which. It is not an error and must not be counted as one.
DEGRADED_SUCCESS = {
    "package": "com.example.app",
    "permissions": ["INTERNET"],
    "degraded": "androguard is not installed; answered the zip-level facts",
}


class _Sink:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append((event_type, data))

    def finished(self) -> dict[str, Any]:
        return [data for name, data in self.events if name == "tool_call_finished"][-1]


def _run(answer: Any, *, raises: bool = False) -> tuple[Any, dict[str, Any]]:
    """One wrapped call, returning its ledger entry and its finished event."""
    sink = _Sink()
    recorder = EvidenceRecorder(
        "static",
        counter=EvidenceCounter(),
        stage="analysis",
        sink=sink,  # type: ignore[arg-type]
    )

    def identify_file(carved_path: str = "") -> str:
        """Name the format of one file."""
        if raises:
            raise RuntimeError("the transport went away")
        return answer if isinstance(answer, str) else json.dumps(answer)

    tool = StructuredTool.from_function(func=identify_file, name="identify_file")
    record_tools([tool], recorder)[0].invoke({"carved_path": "body_0x364000"})
    return recorder.entries[-1], sink.finished()


class TestTheLedgerAndTheEventAgree:
    def test_a_returned_structured_error_is_a_failure_on_both(self) -> None:
        entry, event = _run(STRUCTURED_ERROR)

        assert entry.ok is False
        assert event["ok"] is False
        assert event["evidence_id"] == entry.id

    def test_a_raised_error_is_a_failure_on_both(self) -> None:
        entry, event = _run(None, raises=True)

        assert entry.ok is False
        assert event["ok"] is False

    def test_a_flat_error_from_another_project_is_a_failure_on_both(self) -> None:
        entry, event = _run(FLAT_ERROR)

        assert entry.ok is False
        assert event["ok"] is False

    def test_a_degraded_answer_is_a_success_on_both(self) -> None:
        """Fewer facts and a note saying which is an answer, not a failure."""
        entry, event = _run(DEGRADED_SUCCESS)

        assert entry.ok is True
        assert event["ok"] is True

    def test_a_plain_answer_is_a_success_on_both(self) -> None:
        entry, event = _run({"file_type": "pe", "platform": "windows"})

        assert entry.ok is True
        assert event["ok"] is True


class TestWhatTheFailureSays:
    def test_the_event_carries_the_remediation_the_entry_kept(self) -> None:
        entry, event = _run(STRUCTURED_ERROR)

        assert entry.remediation == "pass the path value carve_payloads returned"
        assert event["summary"] == "the call failed; pass the path value carve_payloads returned"

    def test_the_error_text_itself_does_not_travel(self) -> None:
        """It is the half that names hosts and paths; the ledger keeps it."""
        _entry, event = _run(STRUCTURED_ERROR)

        assert "/srv/staging" not in event["summary"]

    def test_a_failure_with_no_remedy_still_says_it_failed(self) -> None:
        _entry, event = _run(FLAT_ERROR)

        assert event["summary"].startswith("the call failed")
