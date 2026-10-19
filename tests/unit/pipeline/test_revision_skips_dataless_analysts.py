"""An analyst with no data must not be revised — it manufactures corroboration.

The analyst node already refuses to run an agent whose loader returned nothing
but its "No <layer> data available for sample <sha>." sentence
(``nodes.py`` / ``_is_placeholder_only``, locked in by
``test_placeholder_skip.py``). The revision node never got the same guard: it
iterates ``agent_registry.list_agents()`` unconditionally, so every negotiation
round re-runs every analyst — including the ones that were just skipped for
having nothing to analyse.

Observed live on 2026-07-29, CAPE unreachable, one round:

    14:32:18  static  ISR revision (round 1)     6m38s
    14:38:56  dynamic ISR revision (round 1)     8m39s   <- no sandbox data at all
    14:47:35  network ISR revision (round 1)     8m03s   <- no PCAP at all
    14:55:38  WARNING Sycophancy detected between 'static' and 'dynamic' (sim=1.000)

The cost is not the wasted quarter hour. ``_revise_one`` hands each agent its
*peers'* reports, so an analyst with no evidence of its own has nothing to write
but what static already said — and it comes back tagged ``domain="dynamic"``.
``CascadeResult.is_corroborated`` is ``len(contributing_layers) >= 2``, so a
single-layer static finding is promoted to CORROBORATED by an analyst that
never saw a byte of dynamic data, and enters at ``LAYER_WEIGHTS["dynamic"]``
= 0.45 — *above* static's own 0.35. sim=1.000 is that echo, measured.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

from maljan.core.config import ChunkingConfig
from maljan.pipeline.nodes import REVISION_INPUT_NOT_LOADED, make_revision_node


@dataclass
class _Chunk:
    content: str
    index: int = 0
    total: int = 1

    def to_prompt_header(self) -> str:
        return f"[chunk {self.index + 1}/{self.total}]"


def _agent(name: str) -> MagicMock:
    """An agent whose ``safe_revise_isr`` records that it was called."""
    agent = MagicMock()
    isr = MagicMock()
    isr.claims = [MagicMock()]
    isr.dissent_items = []
    agent.safe_revise_isr.return_value = (f"{name} revised text", isr)
    return agent


def _container(chunks_by_agent: dict[str, list[_Chunk]]) -> MagicMock:
    container = MagicMock()
    container.is_mock = False
    container.agent_registry.list_agents.return_value = list(chunks_by_agent)
    container.analyst_keys.return_value = list(chunks_by_agent)
    container.agent_role.side_effect = lambda n: n
    container.config.llm.parallel_analysts = False
    agents = {name: _agent(name) for name in chunks_by_agent}
    container.get_agent.side_effect = lambda n: agents[n]
    container.config.chunking = ChunkingConfig(overlap_tokens=0)

    def for_agent(name: str, *, sandbox_report: Any = None, **_kw: Any) -> list[_Chunk]:
        # The sandbox slice where a report is given, as round 0 reads it; the
        # sample's own data otherwise.
        if sandbox_report:
            return container.load_sandbox_data_for_agent(name, sandbox_report)
        return chunks_by_agent[name]

    container.load_data_for_agent.side_effect = for_agent
    container._agents = agents  # test handle
    return container


def _state() -> dict[str, Any]:
    return {
        "file_hash": "abc123",
        "iteration_count": 1,
        "discussion_history": [],
        "reports": {
            "static": "PE32 with VirtualAllocEx, WriteProcessMemory, CreateRemoteThread.",
            "dynamic": "",
            "network": "",
        },
        "isr_reports": {},
    }


_REAL_DATA = [_Chunk(content="PE32 executable, 9 sections, imports VirtualAllocEx.")]


def _placeholder(layer: str) -> list[_Chunk]:
    return [_Chunk(content=f"No {layer} data available for sample abc123.")]


def _run(container: MagicMock) -> dict[str, Any]:
    node = make_revision_node(container)
    return asyncio.run(node(_state()))


class TestADatalessAnalystIsNotRevised:
    def test_the_analyst_with_only_a_placeholder_is_skipped(self) -> None:
        c = _container(
            {"static": _REAL_DATA, "dynamic": _placeholder("dynamic"), "network": _REAL_DATA}
        )
        _run(c)

        assert c._agents["static"].safe_revise_isr.called
        assert c._agents["network"].safe_revise_isr.called
        assert not c._agents["dynamic"].safe_revise_isr.called, (
            "dynamic has no sandbox data; revising it can only echo its peers"
        )

    def test_every_dataless_analyst_is_skipped(self) -> None:
        c = _container(
            {
                "static": _REAL_DATA,
                "dynamic": _placeholder("dynamic"),
                "network": _placeholder("network"),
            }
        )
        _run(c)

        assert c._agents["static"].safe_revise_isr.called
        assert not c._agents["dynamic"].safe_revise_isr.called
        assert not c._agents["network"].safe_revise_isr.called

    def test_an_analyst_with_no_chunks_at_all_is_skipped(self) -> None:
        c = _container({"static": _REAL_DATA, "dynamic": []})
        _run(c)

        assert not c._agents["dynamic"].safe_revise_isr.called


class TestTheSkipDoesNotFabricateOrDestroyContent:
    def test_the_skipped_analyst_keeps_its_original_report(self) -> None:
        """Skipping must not blank a report the rest of the pipeline reads."""
        c = _container({"static": _REAL_DATA, "dynamic": _placeholder("dynamic")})
        out = _run(c)

        assert out["revised_reports"]["dynamic"] == _state()["reports"]["dynamic"]

    def test_the_skipped_analyst_emits_an_empty_isr_not_a_missing_key(self) -> None:
        """``zip(..., strict=True)`` downstream means every agent must be present."""
        c = _container({"static": _REAL_DATA, "dynamic": _placeholder("dynamic")})
        out = _run(c)

        assert set(out["isr_reports"]) == {"static", "dynamic"}
        assert not out["isr_reports"]["dynamic"].claims, (
            "a skipped analyst must contribute no claims — claims are what "
            "reach the cascade as a contributing layer"
        )


class TestStaticIsNeverSkipped:
    """Mirrors ``_is_placeholder_only``'s static carve-out.

    When a sample cannot be mirrored for the Ghidra container the loader
    returns the placeholder for static too, and static is *meant* to fall back
    to a metadata-only prompt. Skipping it here would delete the primary
    analyst on exactly the runs that most need whatever it can still say.
    """

    def test_static_is_revised_even_on_a_placeholder(self) -> None:
        c = _container({"static": _placeholder("static"), "dynamic": _REAL_DATA})
        _run(c)

        assert c._agents["static"].safe_revise_isr.called


class TestAnInputThatCannotBeLoadedIsNotRevisedAndIsSaid:
    """A revision is not made on a text it cannot read; the first answer stands, said.

    Unknown data is not absent data, so the analyst keeps its round-0 answer
    and claims (never an empty ISR in their place), and the run records why:
    on the round's record, on the stage record and, through the truncation
    ledger, in the degradation reasons the judge assembles.
    """

    def _run_failing(self) -> tuple[MagicMock, dict[str, Any], MagicMock]:
        c = _container({"static": _REAL_DATA, "dynamic": _REAL_DATA})
        c.load_data_for_agent.side_effect = RuntimeError("qdrant down")
        round0 = _isr_with(3)
        out = _run_with(c, _state_with_round0({"dynamic": round0}))
        return c, out, round0

    def test_the_analyst_is_not_revised_and_keeps_its_claims(self) -> None:
        c, out, round0 = self._run_failing()

        assert not c._agents["dynamic"].safe_revise_isr.called
        assert out["isr_reports"]["dynamic"] is round0

    def test_the_reason_is_on_the_round_record_and_in_the_ledger(self) -> None:
        c, out, _ = self._run_failing()

        reason = REVISION_INPUT_NOT_LOADED.format(reason="RuntimeError")
        assert out["revision_rounds"][0]["not_revised"]["dynamic"] == reason
        (sentence,) = [
            call.args[0]
            for call in c.get_truncation_ledger().record_input_shortened.call_args_list
            if "dynamic" in call.args[0]
        ]
        assert sentence == (
            f"The dynamic analyst's round-1 revision was not made: {reason}; "
            "its first answer stands."
        )
        assert "qdrant down" not in sentence

    def test_the_reason_is_on_the_stage_record(self) -> None:
        import time
        from types import SimpleNamespace

        from maljan.pipeline.nodes import _debate_record

        record = _debate_record(
            SimpleNamespace(key="debate"), time.monotonic(), agent_reasons={"dynamic": "why"}
        )
        entry = record["stage_results"]["debate"]
        assert entry["agent_reasons"] == {"dynamic": "why"}
        assert not entry.get("failure")


# ---------------------------------------------------------------------------
# BUG 12 (live 2026-09-07): an analyst that ran on round 0 and produced claims
# came out of the revision round with none, and the report's degradation text
# said "analysts produced no claims".
#
# The two rounds read different inputs. Round 0 for dynamic/network uses
# `load_sandbox_data_for_agent(agent, sandbox_report)` whenever a sandbox
# report exists; `_revision_input_is_absent` only ever consulted
# `load_chunked`, which for those layers is the file loader's own
# "No <layer> data available" placeholder on a live sample. So the guard read
# "no data" for an analyst that had a full detonation report, and the skip
# branch replaced its ISR with `_empty_isr` — wiping claims that were already
# made rather than merely declining to make new ones.
#
# Two separate rules come out of it: the guard must ask the same question
# round 0 asked, and no branch may replace a report that carries claims with
# an empty ISR. Declining to *revise* is fine; deleting is not.
# ---------------------------------------------------------------------------


def _isr_with(claim_count: int) -> MagicMock:
    isr = MagicMock()
    isr.claims = [MagicMock() for _ in range(claim_count)]
    isr.dissent_items = []
    return isr


def _state_with_round0(isr_reports: dict[str, Any]) -> dict[str, Any]:
    state = _state()
    state["reports"]["dynamic"] = "Injected into explorer.exe; contacted 10.0.0.5:443."
    state["isr_reports"] = isr_reports
    return state


def _run_with(container: MagicMock, state: dict[str, Any]) -> dict[str, Any]:
    node = make_revision_node(container)
    return asyncio.run(node(state))


class TestRoundZeroClaimsSurviveTheRevisionRound:
    def test_an_analyst_that_ran_on_the_sandbox_report_keeps_its_claims(self) -> None:
        """The live case: dynamic analysed a full detonation report on round 0,
        and `load_chunked` — the only source the guard looked at — says
        "No dynamic data available"."""
        c = _container({"static": _REAL_DATA, "dynamic": _placeholder("dynamic")})
        c.load_sandbox_data_for_agent.return_value = [_Chunk(content='{"processes": [1, 2]}')]

        round0 = _isr_with(4)
        state = _state_with_round0({"dynamic": round0, "static": _isr_with(2)})
        state["sandbox_report"] = {"behavior": {"processes": [{"pid": 1}]}}

        out = _run_with(c, state)

        assert out["isr_reports"]["dynamic"].claims, (
            "dynamic's four round-0 claims were replaced by an empty ISR: the "
            "revision guard read a different data source than round 0 did"
        )

    def test_the_guard_sees_the_sandbox_report_as_data(self) -> None:
        """The guard itself, directly: a sandbox report present means the
        analyst had data, whatever the file loader says."""
        from maljan.pipeline.nodes import _revision_input_is_absent

        c = _container({"dynamic": _placeholder("dynamic")})
        c.load_sandbox_data_for_agent.return_value = [_Chunk(content='{"processes": []}')]
        state = _state()
        state["sandbox_report"] = {"behavior": {}}

        assert _revision_input_is_absent(state, c, "dynamic") is False

    def test_without_a_sandbox_report_the_loader_check_still_applies(self) -> None:
        """(b) A truly data-less analyst: no sandbox report, loader placeholder
        only. It is skipped, and it stays empty."""
        from maljan.pipeline.nodes import _revision_input_is_absent

        c = _container({"static": _REAL_DATA, "dynamic": _placeholder("dynamic")})
        state = _state()

        assert _revision_input_is_absent(state, c, "dynamic") is True

        out = _run_with(c, state)
        assert not c._agents["dynamic"].safe_revise_isr.called
        assert out["isr_reports"]["dynamic"].claims == []

    def test_a_skip_never_replaces_an_isr_that_carries_claims(self) -> None:
        """The second rule, independent of which source the guard reads: even a
        correctly skipped analyst keeps whatever it already claimed."""
        c = _container({"static": _REAL_DATA, "dynamic": _placeholder("dynamic")})
        round0 = _isr_with(3)
        state = _state_with_round0({"dynamic": round0})

        out = _run_with(c, state)

        assert not c._agents["dynamic"].safe_revise_isr.called, "skipping the revise is correct"
        assert out["isr_reports"]["dynamic"] is round0, (
            "the round-0 ISR must be carried forward untouched, not replaced"
        )


class TestTheDataLessDistinctionIsCarriedAsDataAndInTheReason:
    """An analyst with nothing to read and one that read and claimed nothing.

    The distinction is carried as data — a per-agent `no_data` flag on
    `run_summary.agent_stats`, rendered as "(no data)" beside the analyst — and
    in the degradation reasons: a skipped analyst is named under "analysts
    skipped (<why>):", and "analysts produced no claims:" names only the ones
    that ran. The node-level check is in `test_degraded_mode_at_the_judge_node`.
    """

    def test_the_skipped_reason_names_its_cause_and_its_analysts(self) -> None:
        from maljan.pipeline.nodes import NO_SANDBOX_DATA_REASON, skipped_analysts_reason

        assert (
            skipped_analysts_reason(NO_SANDBOX_DATA_REASON, ["dynamic", "network"])
            == "analysts skipped (no sandbox data): dynamic, network"
        )

    def test_the_report_reads_a_skipped_reason_back(self) -> None:
        from maljan.reporting.renderers.markdown import _skipped_after

        assert _skipped_after(["analysts skipped (no sandbox data): dynamic, network"]) == [
            ("no sandbox data", ["dynamic", "network"])
        ]
        assert _skipped_after(["analysts produced no claims: static"]) == []

    def test_the_reason_string_stays_partitionable(self) -> None:
        """The degradation reason keeps the shape a reader partitions on."""
        from maljan.analysis.run_summary import RunSummaryBuilder

        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_verdict("Suspicious", 0)
            .set_degraded_mode(True, ["analysts produced no claims: dynamic, network"])
            .build()
        )
        reason = summary.degradation_reasons[0]
        head, sep, tail = reason.partition("analysts produced no claims:")
        assert sep and not head.strip()
        assert {p.strip() for p in tail.split(",")} == {"dynamic", "network"}

    def test_a_dataless_analyst_is_flagged_in_agent_stats(self) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder

        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_verdict("Suspicious", 0)
            .set_isr_stats(
                {"dynamic": _stub_isr("dynamic", 0), "static": _stub_isr("static", 3)},
                no_data={"dynamic"},
            )
            .build()
        )
        by_agent = {s.agent_id: s for s in summary.agent_stats}
        assert by_agent["dynamic"].no_data is True
        assert by_agent["static"].no_data is False

        payload = summary.to_dict()["agent_stats"]
        assert {row["agent_id"]: row["no_data"] for row in payload} == {
            "dynamic": True,
            "static": False,
        }

    def test_the_markdown_says_no_data_beside_that_analyst(self) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder

        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_verdict("Suspicious", 0)
            .set_isr_stats(
                {"dynamic": _stub_isr("dynamic", 0), "static": _stub_isr("static", 3)},
                no_data={"dynamic"},
            )
            .build()
        )
        rows = [line for line in summary.to_markdown().splitlines() if line.startswith("| dynamic")]
        assert rows and "(no data)" in rows[0]
        static_rows = [
            line for line in summary.to_markdown().splitlines() if line.startswith("| static")
        ]
        assert static_rows and "(no data)" not in static_rows[0]

    def test_omitting_the_flag_keeps_every_analyst_unflagged(self) -> None:
        """Existing callers pass no `no_data` at all, and must be unaffected."""
        from maljan.analysis.run_summary import RunSummaryBuilder

        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_verdict("Suspicious", 0)
            .set_isr_stats({"static": _stub_isr("static", 1)})
            .build()
        )
        assert summary.agent_stats[0].no_data is False
        assert "(no data)" not in summary.to_markdown()


def _stub_isr(name: str, claim_count: int) -> Any:
    isr = MagicMock()
    isr.agent_id = name
    isr.domain = name
    isr.revision_round = 0
    isr.claims = [MagicMock(technique_id=None) for _ in range(claim_count)]
    isr.mean_confidence = 0.5
    isr.dissent_items = []
    return isr
