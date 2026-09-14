"""A stage's reason answers why it did not run, and nothing else.

Live run 2, ``run_summary.stages``: the analysis row read ``ran: true`` with
``reason: "no sandbox fixture for this sample"`` and a 119-second duration. The
reason belonged to two of its three analysts, not to the stage, and a reader
comparing the three fields could only conclude that one of them was lying.

A member's skip reason is recorded per agent — and, for the analyst that had
nothing to read, on its own findings row as ``status_reason``.
"""

from __future__ import annotations

from types import SimpleNamespace

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
