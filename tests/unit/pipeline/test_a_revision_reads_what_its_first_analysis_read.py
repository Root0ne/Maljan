"""A revision round reads the input the analyst's first analysis read.

``_build_revision_context`` asked ``container.load_chunked`` for the agent's
data, which on a live sample is the file loader's "No <agent> data available"
sentence: a dynamic analyst that had analysed a full detonation report was
revised beside RAW DATA that said there was none. The revision now builds its
input through the function round 0 builds it with (``_analyst_input``: the
agent's sources with the sandbox report, the sample path written into a
sample-fed head), and an analyst whose first analysis had no input is told so
in words, never shown the loader's placeholder as if it were data.

Every value is synthetic.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.pipeline import nodes
from maljan.pipeline.nodes import _build_revision_context, _revision_input_is_absent
from tests.unit._chunking_doubles import _container

PLACEHOLDER = "No {role} data available for sample abc."


def _double(role: str, *, room: int | None = None) -> Any:
    container = _container(role=role, sample=PLACEHOLDER.format(role=role))
    agent = MagicMock()
    agent._input_room_chars.side_effect = lambda _text: room
    agent._resolved.static_provider_id = None
    container.get_agent.return_value = agent
    return container


def _state(**over: Any) -> dict[str, Any]:
    return {"file_hash": "abc", "reports": {"agent": "the first answer"}, **over}


class TestTheRevisionReadsTheFirstInput:
    def test_a_sandbox_fed_analyst_reads_the_sandbox_report(self) -> None:
        container = _double("dynamic")
        report = {"behavior": {"processes": [{"name": "dropper.exe"}]}}

        context = _build_revision_context(_state(sandbox_report=report), container, "agent")

        assert "dropper.exe" in context
        assert "data available" not in context

    def test_a_sample_fed_analyst_reads_its_head_with_the_sample_path(self) -> None:
        container = _double("static")

        context = _build_revision_context(
            _state(sample_path="/samples/abc.bin"), container, "agent"
        )

        head = json.loads(context)
        assert head["analysis_file_path"] == "/samples/abc.bin"
        assert head["sha256"] == "abc"

    def test_the_load_is_the_one_round_zero_makes(self) -> None:
        container = _double("dynamic")
        container.load_data_for_agent = MagicMock(return_value=[])
        report = {"behavior": {"x": 1}}

        _build_revision_context(
            _state(sandbox_report=report, sample_path="/samples/abc.bin"), container, "agent"
        )

        kwargs = container.load_data_for_agent.call_args.kwargs
        assert kwargs["file_hash"] == "abc"
        assert kwargs["sandbox_report"] == report
        assert kwargs["sample_path"] == "/samples/abc.bin"


class TestAnAbsentInputIsSaid:
    def test_no_input_is_said_not_shown_as_the_placeholder(self) -> None:
        container = _double("network")

        context = _build_revision_context(_state(), container, "agent")

        assert "data available" not in context
        assert context.startswith("None.")
        assert "no data for this agent" in context

    def test_a_synthetic_sandbox_report_is_said(self) -> None:
        container = _double("dynamic")
        report = {"behavior": {}, "synthetic": True}

        context = _build_revision_context(_state(sandbox_report=report), container, "agent")

        assert context.startswith("None.")

    def test_a_load_that_fails_is_said(self) -> None:
        container = _double("dynamic")
        container.load_data_for_agent = MagicMock(side_effect=RuntimeError("store down"))

        context = _build_revision_context(_state(), container, "agent")

        assert context.startswith("None.")
        assert "could not be loaded" in context
        container.load_data.assert_not_called()


_SANDBOX = {"behavior": {"processes": [{"name": "x.exe"}]}, "network": {"dns": [{"q": "a.test"}]}}


class TestTheGuardIsRoundZeros:
    """The revision's no-data decision is round 0's, for every way an agent reads its input.

    Asked of the input the first analysis builds (``_analyst_input``) and the
    guard it is judged by (``_input_absence``): an agent pointed at the
    sample path by ``data_sources`` is not skipped, and one round 0 skipped
    is not revised.
    """

    @pytest.mark.parametrize(
        ("role", "sources", "sandbox", "skipped"),
        [
            ("dynamic", ["sample.path"], None, False),
            ("dynamic", ["sample.path"], _SANDBOX, False),
            ("network", ["sample.path", "sandbox.network"], {"behavior": {}}, False),
            ("dynamic", ["sample.chunks"], _SANDBOX, True),
            ("network", ["sample.chunks"], None, True),
            ("dynamic", None, _SANDBOX, False),
            ("network", None, None, True),
            ("generic", ["sandbox.network"], None, True),
        ],
    )
    def test_the_revision_skips_exactly_what_round_zero_skipped(
        self, role: str, sources: list[str] | None, sandbox: Any, skipped: bool
    ) -> None:
        container = _container(
            role=role, sample="No agent data available for sample abc.", sources=sources
        )
        agent = MagicMock()
        agent._input_room_chars.side_effect = lambda _text: None
        agent._resolved.static_provider_id = None
        container.get_agent.return_value = agent
        state = _state(sample_path="/samples/abc.bin")
        if sandbox is not None:
            state["sandbox_report"] = sandbox

        chunks = nodes._analyst_input(
            state,
            container,
            "agent",
            role,
            provider_id=None,
            file_hash="abc",
            room=nodes.input_room_of(agent),
            block="",
        )
        round_zero = bool(nodes._input_absence(chunks, role, state))

        assert round_zero is skipped
        assert _revision_input_is_absent(state, container, "agent") is skipped
        assert _build_revision_context(state, container, "agent").startswith("None.") is skipped


class TestASkipIsSaidByWhatWasMissing:
    """The cause a skipped analyst is named under is the fact, not its role.

    "no sandbox data" when the sandbox report is synthetic or missing and every
    source the agent reads is a part of it; "no input data" otherwise. The
    analysis node's line and the judge's degradation reason read one rule.
    """

    @staticmethod
    def _cause(role: str, sources: list[str] | None, report: Any) -> str:
        container = _container(role=role, sample="", sources=sources)
        state = _state()
        if report is not None:
            state["sandbox_report"] = report
        return nodes._skip_cause(container, "agent", role, state)

    def test_dynamic_reading_the_sample_beside_a_real_report_lacked_input(self) -> None:
        assert self._cause("dynamic", ["sample.chunks"], _SANDBOX) == nodes.NO_INPUT_DATA_REASON

    def test_generic_reading_the_network_block_with_no_report_lacked_sandbox_data(self) -> None:
        assert self._cause("generic", ["sandbox.network"], None) == nodes.NO_SANDBOX_DATA_REASON

    def test_a_synthetic_report_is_no_sandbox_data_for_a_sandbox_role(self) -> None:
        cause = self._cause("dynamic", None, {"synthetic": True})
        assert cause == nodes.NO_SANDBOX_DATA_REASON

    def test_a_sandbox_role_beside_a_real_report_lacked_input(self) -> None:
        assert self._cause("network", None, _SANDBOX) == nodes.NO_INPUT_DATA_REASON
