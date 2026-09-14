"""A stage's reason answers why it did not run, and nothing else.

Live run 2, ``run_summary.stages``: the analysis row read ``ran: true`` with
``reason: "no sandbox fixture for this sample"`` and a 119-second duration. The
reason belonged to two of its three analysts, not to the stage, and a reader
comparing the three fields could only conclude that one of them was lying.

A member's skip reason is recorded per agent — and, for the analyst that had
nothing to read, on its own findings row as ``status_reason``.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

from maljan.pipeline.nodes import stage_record
from maljan.pipeline.state import _merge_stage_results

_STAGE = SimpleNamespace(key="analysis", kind="analysis", mode="parallel", agents=("static",))


def _entry(record: dict) -> dict:
    return record["stage_results"]["analysis"]


class TestAStageThatRan:
    def test_a_reason_given_for_it_becomes_the_agent_s(self) -> None:
        entry = _entry(
            stage_record(
                _STAGE, ran=True, reason="no sandbox fixture for this sample", agents=("dynamic",)
            )
        )
        assert entry["reason"] == ""
        assert entry["agent_reasons"] == {"dynamic": "no sandbox fixture for this sample"}

    def test_a_per_agent_reason_is_kept_as_given(self) -> None:
        entry = _entry(
            stage_record(
                _STAGE,
                ran=True,
                agents=("network",),
                agent_reasons={"network": "no data for this agent"},
            )
        )
        assert entry["reason"] == ""
        assert entry["agent_reasons"] == {"network": "no data for this agent"}

    def test_a_stage_whose_members_all_worked_records_none(self) -> None:
        entry = _entry(stage_record(_STAGE, ran=True, agents=("static",), claim_count=4))
        assert entry["reason"] == ""
        assert "agent_reasons" not in entry


class TestAStageThatDidNotRun:
    def test_its_reason_is_the_stage_s(self) -> None:
        entry = _entry(stage_record(_STAGE, ran=False, reason="the profile disables it"))
        assert entry["reason"] == "the profile disables it"
        assert "agent_reasons" not in entry


class TestTheParallelStageMerges:
    def test_each_member_keeps_its_own_reason(self) -> None:
        left = stage_record(
            _STAGE, ran=True, agents=("dynamic",), agent_reasons={"dynamic": "no sandbox"}
        )["stage_results"]
        right = stage_record(
            _STAGE, ran=True, agents=("network",), agent_reasons={"network": "no pcap"}
        )["stage_results"]

        merged = _merge_stage_results(left, right)["analysis"]

        assert merged["agent_reasons"] == {"dynamic": "no sandbox", "network": "no pcap"}
        assert merged["agents"] == ["dynamic", "network"]
        assert merged["reason"] == ""

    def test_an_analyst_that_worked_adds_no_reason(self) -> None:
        left = stage_record(
            _STAGE, ran=True, agents=("dynamic",), agent_reasons={"dynamic": "no sandbox"}
        )["stage_results"]
        right = stage_record(_STAGE, ran=True, agents=("static",), claim_count=3)["stage_results"]

        merged = _merge_stage_results(left, right)["analysis"]

        assert merged["agent_reasons"] == {"dynamic": "no sandbox"}
        assert merged["claim_count"] == 3


class TestTheRollupRow:
    def test_it_carries_the_per_agent_reasons(self) -> None:
        from maljan.pipeline.nodes import stage_rollup

        class _Container:
            def active_profile(self) -> object:
                return SimpleNamespace(stages=[_STAGE])

        state = {
            "stage_results": stage_record(
                _STAGE,
                ran=True,
                agents=("dynamic",),
                agent_reasons={"dynamic": "no sandbox fixture for this sample"},
                duration_ms=119068,
            )["stage_results"]
        }

        (row,) = stage_rollup(_Container(), state)  # type: ignore[arg-type]

        assert row["ran"] is True
        assert row["reason"] == ""
        assert row["agent_reasons"] == {"dynamic": "no sandbox fixture for this sample"}

    def test_a_stage_with_nothing_to_explain_has_no_such_key(self) -> None:
        from maljan.pipeline.nodes import stage_rollup

        class _Container:
            def active_profile(self) -> object:
                return SimpleNamespace(stages=[_STAGE])

        state = {
            "stage_results": stage_record(_STAGE, ran=True, agents=("static",))["stage_results"]
        }

        (row,) = stage_rollup(_Container(), state)  # type: ignore[arg-type]

        assert "agent_reasons" not in row


class TestAStageThatRanAndFailed:
    """The other reason a stage gives: it ran and went wrong. A mediation that
    times out is the debate's own failure, not one of its members'. The first
    version of this rule redirected it onto an empty agent list and blanked it,
    so the only reason the debate stage ever writes stopped appearing at all."""

    def test_a_failure_reason_stays_the_stage_s(self) -> None:
        entry = _entry(stage_record(_STAGE, ran=True, reason="mediation timed out", failure=True))
        assert entry["reason"] == "mediation timed out"
        assert "agent_reasons" not in entry

    def test_the_debate_round_records_its_own_failure(self) -> None:
        from maljan.pipeline.nodes import _debate_record

        debate = SimpleNamespace(key="debate", kind="debate", mode="sequential", agents=("judge",))
        record = _debate_record(debate, time.monotonic(), reason="mediation timed out")

        assert record["stage_results"]["debate"]["ran"] is True
        assert record["stage_results"]["debate"]["reason"] == "mediation timed out"

    def test_a_round_that_went_fine_gives_no_reason(self) -> None:
        from maljan.pipeline.nodes import _debate_record

        debate = SimpleNamespace(key="debate", kind="debate", mode="sequential", agents=("judge",))
        record = _debate_record(debate, time.monotonic())

        assert record["stage_results"]["debate"]["reason"] == ""

    def test_the_rollup_carries_it(self) -> None:
        from maljan.pipeline.nodes import _debate_record, stage_rollup

        debate = SimpleNamespace(key="debate", kind="debate", mode="sequential", agents=("judge",))

        class _Container:
            def active_profile(self) -> object:
                return SimpleNamespace(stages=[debate])

        state = {
            "stage_results": _debate_record(debate, time.monotonic(), reason="mediation failed")[
                "stage_results"
            ]
        }

        (row,) = stage_rollup(_Container(), state)  # type: ignore[arg-type]

        assert row["reason"] == "mediation failed"

    def test_an_unattributable_reason_is_dropped_with_a_word(self, caplog: Any) -> None:
        """The silence is what hid the regression; a debug line would have shown it."""
        import logging

        with caplog.at_level(logging.DEBUG, logger="maljan"):
            entry = _entry(stage_record(_STAGE, ran=True, reason="no sandbox fixture"))

        assert entry["reason"] == ""
        assert "no agent to attribute it to" in caplog.text
