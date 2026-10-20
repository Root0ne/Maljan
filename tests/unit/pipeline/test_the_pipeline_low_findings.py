"""The low-severity pipeline findings (AUD-7b, AUD-10, AUD-13, AUD-17), one test each.

Each test names the finding it pins and is written to fail on the code the
finding describes.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.pipeline.validation import (
    CapabilityGrounding,
    EntryTexts,
    _category_says_benign,
    keep_known_keys,
    key_finding_citation_violations,
    masked_values,
)

# --- AUD-10 (validation.py V1-5..9) -----------------------------------------


def test_v1_5_a_long_run_with_one_separator_is_masked_in_linear_time() -> None:
    hostile = "a/" + "b" * 60_000
    started = time.perf_counter()
    masked_values(hostile)
    assert time.perf_counter() - started < 1.0
    # The shape it reads is unchanged: a path with two separators is blanked.
    assert masked_values("see /SSH/Auth/Credentials now") == "see" + " " * 22 + " now"


class _Report:
    """A report whose ``sections`` cannot be read, after its matrix already grounded a technique."""

    ttp_mappings: list[Any] = []
    capability_matrix = [
        SimpleNamespace(technique_id="T1055", technique_name="Process Injection", not_published="")
    ]
    static = None
    dynamic = None
    network = None
    persistence: list[Any] = []

    @property
    def sections(self) -> Any:
        raise RuntimeError("sections are unreadable")


def test_v1_6_an_unread_grounding_keeps_the_rule_only_rows_already_complete() -> None:
    from maljan.pipeline.validation import rule_match_statement_violations

    class _RuleReport(_Report):
        run_summary = {"corroboration": {"T1003": {"asserted_by": ["yara"], "claimed_by": []}}}
        rule_match_strings = {"T1003": [{"rule": "r", "strings": 1, "layers": ["yara"]}]}
        ttp_mappings = [
            SimpleNamespace(technique_id="T1003", technique_name="OS Credential Dumping")
        ]
        capability_matrix: list[Any] = []

    grounding = CapabilityGrounding.from_report(_RuleReport())
    assert grounding.unread
    found = rule_match_statement_violations(
        "The sample performs OS Credential Dumping (T1003) on the host.", grounding
    )
    assert len(found) == 1


def test_v1_6_an_unreadable_run_is_a_grounding_that_checks_nothing_and_says_why() -> None:
    grounding = CapabilityGrounding.from_report(_Report())
    assert grounding.unread.startswith("RuntimeError")
    # Not the half of the run read before the failure.
    assert not grounding.technique_ids and not grounding.evidence_keys
    assert not grounding.evidence_text


class _Inner(BaseModel):
    model_config = ConfigDict(extra="forbid")
    a: int = 0


class _Outer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    maybe: list[_Inner] | None = None
    grouped: dict[str, list[_Inner]] = {}


def test_v1_7_models_nested_in_a_generic_are_narrowed_too() -> None:
    kept, dropped = keep_known_keys(
        _Outer,
        {
            "maybe": [{"a": 1, "extra": 2}],
            "grouped": {"k": [{"a": 3, "invented": 4}]},
        },
    )
    assert kept == {"maybe": [{"a": 1}], "grouped": {"k": [{"a": 3}]}}
    assert dropped == ["maybe.0.extra", "grouped.k.0.invented"]


def test_v1_9_a_key_finding_citation_is_compared_as_a_citation_is() -> None:
    payload = {"key_findings": [{"evidence_ids": ["[EV_0001]", " ev_0002 "]}]}
    assert key_finding_citation_violations(payload, ["ev_0001", "ev_0002"]) == []
    unknown = {"key_findings": [{"evidence_ids": ["[ev_0009]"]}]}
    assert len(key_finding_citation_violations(unknown, ["ev_0001"])) == 1


# --- AUD-7b (validation.py) -------------------------------------------------


def test_7b_a_category_is_benign_by_whole_words_not_substrings() -> None:
    assert _category_says_benign("legitimate-utility") is True
    assert _category_says_benign("illegitimate-remote-access") is False
    assert _category_says_benign("fake system cleaner (rogue security software)") is False
    for word in ("benignware", "Benignware", "cleanware", "harmlessware"):
        assert _category_says_benign(word) is True, word
    assert _category_says_benign("Potentially unwanted") is False


def test_7b_a_holding_lookup_reads_only_the_entries_that_may_hold_the_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    texts = {f"ev_{i:04d}": f"filler entry number {i}" for i in range(1, 300)}
    texts["ev_0300"] = "contacts needle.example.org once"
    texts["ev_0150"] = texts["ev_0150"] + " also needle.example.org"
    entries = EntryTexts(texts=texts)
    reads: list[str] = []
    real = EntryTexts.holds

    def _counting(self: EntryTexts, entry_id: str, *args: Any, **kwargs: Any) -> bool:
        reads.append(entry_id)
        return real(self, entry_id, *args, **kwargs)

    monkeypatch.setattr(EntryTexts, "holds", _counting)
    assert entries.holding("needle.example.org") == ["ev_0150", "ev_0300"]
    assert len(reads) <= 2


# --- AUD-13 (nodes.py N7-N9, state.py) --------------------------------------


class _Tool:
    name = "count_sections"
    metadata: dict[str, Any] = {}

    def __init__(self) -> None:
        self.asked: list[dict[str, Any]] = []

    async def ainvoke(self, args: dict[str, Any]) -> str:
        self.asked.append(args)
        return "{}"


def test_n7_a_staging_failure_is_the_failure_not_the_tools_file_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.agents import composition
    from maljan.core import config as config_module
    from maljan.core.config import MCPServerConfig
    from maljan.core.pack_steps import effective_steps
    from maljan.pipeline.nodes import _server_step_call
    from tests.unit.pipeline.test_the_pack_runs_its_declared_steps import (
        INVENTORY,
        TestAnInventedToolAsAStep,
        TestTheServerStepCall,
    )

    held = Settings(_env_file=None)
    held.mcp.servers["inventory"] = MCPServerConfig.model_validate(INVENTORY)
    monkeypatch.setattr(config_module, "_settings_instance", held)
    tool = _Tool()
    container = TestTheServerStepCall()._container(held, tool, monkeypatch)  # noqa: SLF001
    monkeypatch.setattr(
        composition,
        "_stage",
        lambda *_a, **_k: ({}, ["sample staging failed for 'inventory': Timeout"]),
    )
    call = _server_step_call(container)
    (step,) = [s for s in effective_steps([TestAnInventedToolAsAStep.STEP]) if s.id == "inventory"]
    answer = call(step, {"sample_path": "/s.exe", "sha256": "", "file_type": "pe"}, None)
    assert answer.ok is False
    assert "sample staging failed for 'inventory': Timeout" in (answer.error or "")
    assert tool.asked == []


def test_n8_a_crashed_pack_publishes_its_type_not_its_message(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import asyncio

    import maljan.pipeline.nodes as nodes
    from tests.unit.pipeline.test_triage_pack import (
        _container,
        _pe,
        _state,
        _triage_stage,
        _write,
    )

    def _explode(*_: Any, **__: Any) -> Any:
        raise RuntimeError("could not open /home/analyst/secret-case/sample.exe")

    monkeypatch.setattr(nodes, "run_pack", _explode)
    container, _ = _container()
    node = nodes.make_triage_node(container, stage=_triage_stage(container))
    update = asyncio.run(node(_state(sample_path=_write(tmp_path, "s.exe", _pe()))))
    reason = update["stage_results"]["triage_pack"]["reason"]
    assert "secret-case" not in reason
    assert reason.startswith("triage pack failed: RuntimeError")


def test_n9_the_failure_header_cuts_nothing_unless_asked() -> None:
    from maljan.pipeline.nodes import tool_failures

    long_message = "trace " * 400
    ledger = [
        SimpleNamespace(
            ok=False,
            repeated_of=None,
            error=f"{long_message}{i}",
            output="",
            tool=f"tool_{i}",
            id=f"ev_{i:04d}",
            server=None,
            remediation=None,
        )
        for i in range(1, 31)
    ]
    rows = tool_failures(ledger)
    assert len(rows) == 30
    assert rows[0]["error"] == f"{long_message}1"
    cut = tool_failures(ledger, limit=5, message_chars=40)
    assert len(cut) == 6 and "and 25 more" in cut[-1]["error"]


def test_n9_a_narrative_round_has_no_wait_of_its_own_until_the_pace_is_measured() -> None:
    from maljan.pipeline.nodes import _narrative_timeout
    from maljan.reporting.narrative_agent import NarrativeAgent

    agent = NarrativeAgent.__new__(NarrativeAgent)
    agent.generation_rates = None  # type: ignore[attr-defined]
    agent.prompt_chars = lambda *_a, **_k: 0  # type: ignore[method-assign]
    assert _narrative_timeout(agent, None, "", "") is None


def test_n9_the_reputation_lookup_waits_as_long_as_the_tool_declares(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import maljan.agents.base_agent as base_agent
    import maljan.core.declared_reading as declared_reading
    from maljan.agents.evidence_recorder import EvidenceRecorder
    from maljan.pipeline.nodes import _reputation_lookup
    from maljan.pipeline.triage_pack import PIPELINE
    from maljan.schemas.evidence import EvidenceCounter

    container = ServiceContainer(Settings(_env_file=None), mock=True)
    waits: list[Any] = []

    class _Registry:
        def tools_for_ref(self, ref: Any, job_id: str, **_: Any) -> tuple[list[Any], list[str]]:
            return [_Tool()], []

    def _blocking(coro: Any, timeout: Any = None, **_: Any) -> str:
        waits.append(timeout)
        coro.close()
        return "{}"

    real = declared_reading.declarations

    class _Declared:
        def __init__(self, held: Any) -> None:
            self._held = held

        def __getattr__(self, name: str) -> Any:
            return getattr(self._held, name)

        def declaration_for(self, key: Any) -> Any:
            return SimpleNamespace(timeout_seconds=7.5)

    monkeypatch.setattr(container, "get_server_registry", lambda: _Registry())
    monkeypatch.setattr(base_agent, "run_coro_blocking", _blocking)
    monkeypatch.setattr(declared_reading, "declarations", lambda *a, **k: _Declared(real(*a, **k)))
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    _reputation_lookup(container, "b" * 64)(recorder)
    assert waits == [7.5]


def test_n_state_a_later_succeeding_round_keeps_the_failure() -> None:
    from maljan.pipeline.state import _merge_stage_results

    merged = _merge_stage_results(
        {"debate": {"ran": True, "failure": True, "reason": "round 1 failed"}},
        {"debate": {"ran": True, "failure": False, "reason": ""}},
    )
    assert merged["debate"]["failure"] is True


# --- AUD-17 (pipeline P-4..7) ------------------------------------------------


def test_p4_only_a_declared_reference_tool_says_an_id_is_not_a_technique() -> None:
    from maljan.pipeline.evidence_summary import invalid_technique_ids

    sample_data = SimpleNamespace(
        id="ev_0001", tool="decompile", structured={"technique_id": "T1055", "valid": False}
    )
    lookup = SimpleNamespace(
        id="ev_0002", tool="attck_lookup", structured={"technique_id": "T9999", "valid": False}
    )
    assert invalid_technique_ids([sample_data, lookup]) == {"T9999"}


def test_p5_p6_a_stopped_run_summary_says_no_verdict_and_what_it_lacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.pipeline import nodes
    from maljan.pipeline.stopped_run import NO_VERDICT_REASON, stopped_run_summary
    from tests.unit.pipeline.test_a_stopped_run_keeps_a_partial_report import NOTE, _state

    container = ServiceContainer(Settings(_env_file=None), mock=True)
    summary = stopped_run_summary(_state(), container, note=NOTE)
    assert NO_VERDICT_REASON in summary["degradation_reasons"]
    judged = stopped_run_summary(_state(final_decision="Malware"), container, note=NOTE)
    assert NO_VERDICT_REASON not in judged["degradation_reasons"]

    def _broken(*_: Any, **__: Any) -> Any:
        raise RuntimeError("no rollup")

    monkeypatch.setattr(nodes, "stage_rollup", _broken)
    lacking = stopped_run_summary(_state(), container, note=NOTE)
    assert any("lacks" in r and "stages" in r for r in lacking["degradation_reasons"])


def test_p6_an_unreadable_ledger_row_is_said_in_the_stopped_report() -> None:
    from maljan.pipeline.stopped_run import partial_report
    from tests.unit.pipeline.test_a_stopped_run_keeps_a_partial_report import NOTE, _state

    container = ServiceContainer(Settings(_env_file=None), mock=True)
    report = partial_report(_state(evidence_ledger=[{"not": "a ledger row"}]), container, note=NOTE)
    assert report is not None
    assert any(
        "could not be read and are not in this report" in reason
        for reason in report["degradation_reasons"]
    )


def test_p7_the_tools_failed_line_merges_repeats() -> None:
    from maljan.pipeline.run_state import render_run_state
    from tests.unit.pipeline.test_run_state import _row

    rows = [_row("capa", "boom", n, ok=False) for n in range(1, 41)]
    body = render_run_state({"file_hash": "c" * 64, "evidence_ledger": rows})
    (line,) = [x for x in body.splitlines() if x.startswith("tools failed:")]
    assert line == "tools failed: capa (pipeline) ×40"


def _staging_call(
    monkeypatch: pytest.MonkeyPatch, reasons: list[str], declared: dict | None = None
):
    from maljan.agents import composition
    from maljan.core import config as config_module
    from maljan.core.config import MCPServerConfig
    from maljan.core.pack_steps import effective_steps
    from maljan.pipeline.nodes import _server_step_call
    from tests.unit.pipeline.test_the_pack_runs_its_declared_steps import (
        INVENTORY,
        TestAnInventedToolAsAStep,
        TestTheServerStepCall,
    )

    held = Settings(_env_file=None)
    held.mcp.servers["inventory"] = MCPServerConfig.model_validate(INVENTORY)
    monkeypatch.setattr(config_module, "_settings_instance", held)
    tool = _Tool()
    container = TestTheServerStepCall()._container(held, tool, monkeypatch)  # noqa: SLF001
    monkeypatch.setattr(composition, "_stage", lambda *_a, **_k: ({}, reasons))
    (step,) = [
        s
        for s in effective_steps([{**TestAnInventedToolAsAStep.STEP, **(declared or {})}])
        if s.id == "inventory"
    ]
    answer = _server_step_call(container)(
        step, {"sample_path": "/s.exe", "sha256": "", "file_type": "pe"}, None
    )
    return answer, tool


def test_n7_another_servers_staging_failure_does_not_fail_this_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answer, tool = _staging_call(monkeypatch, ["sample staging failed for 'elsewhere': Timeout"])
    assert answer.ok is True
    assert len(tool.asked) == 1


def test_n7_a_step_that_never_uses_the_sample_path_is_not_failed_by_staging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answer, tool = _staging_call(
        monkeypatch,
        ["sample staging failed for 'inventory': Timeout"],
        declared={"arguments": {"n": 3}},
    )
    assert answer.ok is True
    assert tool.asked == [{"n": 3}]


def test_n9_the_reputation_lookup_falls_back_to_what_is_left_of_the_pack_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import maljan.agents.base_agent as base_agent
    import maljan.core.declared_reading as declared_reading
    from maljan.agents.evidence_recorder import EvidenceRecorder
    from maljan.pipeline.nodes import _reputation_lookup
    from maljan.pipeline.triage_pack import PIPELINE
    from maljan.schemas.evidence import EvidenceCounter

    container = ServiceContainer(Settings(_env_file=None), mock=True)
    waits: list[Any] = []

    class _Registry:
        def tools_for_ref(self, ref: Any, job_id: str, **_: Any) -> tuple[list[Any], list[str]]:
            return [_Tool()], []

    def _blocking(coro: Any, timeout: Any = None, **_: Any) -> str:
        waits.append(timeout)
        coro.close()
        return "{}"

    real = declared_reading.declarations

    class _Declared:
        def __init__(self, held: Any) -> None:
            self._held = held

        def __getattr__(self, name: str) -> Any:
            return getattr(self._held, name)

        def declaration_for(self, key: Any) -> Any:
            return SimpleNamespace(timeout_seconds=None)

    monkeypatch.setattr(container, "get_server_registry", lambda: _Registry())
    monkeypatch.setattr(base_agent, "run_coro_blocking", _blocking)
    monkeypatch.setattr(declared_reading, "declarations", lambda *a, **k: _Declared(real(*a, **k)))
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    _reputation_lookup(container, "b" * 64)(recorder, left=42.0)
    assert waits == [42.0]


def test_n9_a_62_kb_failure_message_is_held_to_the_result_budget_and_says_so() -> None:
    from maljan.pipeline.nodes import tool_failures
    from maljan.schemas.evidence import build_entry

    trace = "Traceback (most recent call last):\n" + '  File "/srv/tool/x.py", line 1\n' * 2000
    entry = build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="static",
        tool="boom",
        args={},
        server="s",
        output="",
        ok=False,
        error=trace,
        max_chars=4000,
    )
    assert len(trace) > 60_000
    assert len(entry.error or "") <= 4000 and (entry.error or "").endswith("…")
    assert entry.truncated is True
    (row,) = tool_failures([entry])
    assert len(row["error"]) <= 4000
