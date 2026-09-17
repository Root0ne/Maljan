"""How a nudge had to be sent travels from the analyst to the run summary.

The analyst node reads the mode off the agent once, puts it on the state's
``nudge_retry_modes`` channel under the agent's name and clears it, because
agents are cached across samples; the run summary renders the channel as
``nudge.retry_mode``.
"""

from __future__ import annotations

import asyncio

from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.pipeline.nodes import make_revision_node, make_stage_agent_node
from maljan.schemas.evidence import EvidenceCounter
from tests.stages import ANALYSIS_STAGE
from tests.unit.pipeline.test_evidence_ledger_channel import (
    _analysis_state,
    _Analyst,
    _Chunk,
    _container,
    _revision_state,
)


def test_the_node_hands_the_mode_over_once() -> None:
    agent = _Analyst("static", EvidenceCounter())
    agent._nudge_retry_mode = "invalid_tool_calls_dropped"
    container = _container({"static": agent}, {"static": [_Chunk("PE32 executable.")]})

    update = make_stage_agent_node(ANALYSIS_STAGE, "static", container)(_analysis_state())

    assert update["nudge_retry_modes"] == {"static": "invalid_tool_calls_dropped"}
    assert agent._nudge_retry_mode is None


def test_a_nudge_repaired_in_a_revision_round_belongs_to_that_round() -> None:
    agent = _Analyst("static", EvidenceCounter())
    container = _container({"static": agent}, {"static": [_Chunk("PE32 executable.")]})
    make_stage_agent_node(ANALYSIS_STAGE, "static", container)(_analysis_state())
    agent._nudge_retry_mode = "tool_choice_none"

    revision = asyncio.run(make_revision_node(container)(_revision_state()))

    assert revision["nudge_retry_modes"] == {"static": "tool_choice_none"}
    assert agent.drain_nudge_retry_mode() is None


def test_an_analyst_that_needed_no_repair_writes_nothing() -> None:
    agent = _Analyst("static", EvidenceCounter())
    container = _container({"static": agent}, {"static": [_Chunk("PE32 executable.")]})

    update = make_stage_agent_node(ANALYSIS_STAGE, "static", container)(_analysis_state())

    assert "nudge_retry_modes" not in update


def test_the_summary_renders_the_channel_and_omits_it_when_empty() -> None:
    with_modes = (
        RunSummaryBuilder(start_time=0.0)
        .set_sample("abc", "s.exe")
        .set_verdict("Malware", 1)
        .set_nudge({"static": "tool_choice_none", "network": ""})
        .build()
        .to_dict()
    )
    assert with_modes["nudge"] == {"retry_mode": {"static": "tool_choice_none"}}
    without = RunSummaryBuilder(start_time=0.0).set_sample("abc", "s.exe").build().to_dict()
    assert without["nudge"] is None
