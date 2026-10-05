"""A revision that is not made, or fails, leaves the analyst's answer in force whole.

After a paid run's spend ceiling latched, every revision was refused, and the
revision node wrote an empty answer over each analyst's first one. A composed
analyst whose revision loop was not started came back with no text and an
empty answer, which replaced its first answer too. The debate then said
"no claims produced" for analysts whose first answers had twenty-three claims,
a key of 25 characters was published as ``***``, and the judge weighed no
technique at all. The first answer now stands when its revision is not made,
the judge reads it, and the debate names each analyst with its real count.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.agents.base_agent import NO_STRUCTURED_REPORT_STATUS
from maljan.core.exceptions import AnalystError
from maljan.core.spend import SpendCeilingStop
from maljan.pipeline import events as ev
from maljan.pipeline.evidence_summary import summarise
from maljan.pipeline.nodes import make_revision_node
from maljan.pipeline.state import _merge_dicts
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.stages import paper_profile

LONG_KEY = "all_tools_reverser_ghidra"
NAMES = ["static", LONG_KEY, "triage"]


def _first(name: str, technique: str, count: int) -> AgentISR:
    return AgentISR(
        agent_id=name,
        domain="static",
        claims=[
            ClaimEvidence(
                claim=f"{name} finding {i}",
                evidence_ref="ev_0001",
                confidence=0.8,
                technique_id=technique if i == 0 else None,
            )
            for i in range(count)
        ],
    )


class _Recorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append((event_type, data))

    def said(self) -> list[dict[str, Any]]:
        return [data for kind, data in self.events if kind == ev.AGENT_MESSAGE]


def _container(recorder: _Recorder, outcomes: dict[str, Any]) -> Any:
    container = MagicMock()
    container.is_mock = False
    container.event_sink = recorder
    container.agent_registry.list_agents.return_value = NAMES
    container.analyst_keys.return_value = NAMES
    container.agent_role.side_effect = lambda n: n
    container.active_profile.return_value = paper_profile(NAMES)
    container.config.llm.parallel_analysts = False
    labels = {LONG_KEY: "Reverser (Ghidra)", "static": "Static analyst", "triage": "Triage"}
    container.config.agents.definitions = {}

    agents: dict[str, Any] = {}
    for name in NAMES:
        agent = MagicMock()
        outcome = outcomes[name]
        if isinstance(outcome, BaseException):
            agent.safe_revise_isr.side_effect = outcome
        else:
            agent.safe_revise_isr.return_value = outcome
        agent.drain_evidence_entries.return_value = []
        agents[name] = agent
    container.get_agent.side_effect = lambda n: agents[n]
    return container, labels


def _state() -> dict[str, Any]:
    return {
        "iteration_count": 1,
        "reports": {name: f"{name} first report" for name in NAMES},
        "isr_reports": {
            "static": _first("static", "T1027", 9),
            LONG_KEY: _first(LONG_KEY, "T1053.005", 23),
            "triage": _first("triage", "T1218.011", 13),
        },
    }


def _run(
    outcomes: dict[str, Any], *, unlabelled: bool = False
) -> tuple[dict[str, Any], dict[str, Any], _Recorder]:
    recorder = _Recorder()
    container, labels = _container(recorder, outcomes)
    if unlabelled:
        labels = {}
    state = _state()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("maljan.pipeline.nodes._revision_input_is_absent", lambda *a: False)
        mp.setattr("maljan.pipeline.nodes.label_of", lambda _c, key: labels.get(key, key))
        update = asyncio.run(make_revision_node(container)(state))
    merged = _merge_dicts(state["isr_reports"], update["isr_reports"])
    return update, merged, recorder


def _refused(name: str) -> AnalystError:
    stop = SpendCeilingStop(
        "a revision call of deepseek-flash was not made: the spend ceiling of 2.0000 USD "
        "is exhausted"
    )
    error = AnalystError(f"{name} ISR revision failed: {stop}")
    error.__cause__ = stop
    return error


class TestARevisionTheCeilingRefused:
    def test_leaves_every_first_answer_for_the_judge(self) -> None:
        empty_composed = ("", AgentISR(agent_id=LONG_KEY, domain="static", claims=[]))
        no_report = (
            "[TRIAGE — round 1] prose without a findings block",
            AgentISR(
                agent_id="triage", domain="static", claims=[], status=NO_STRUCTURED_REPORT_STATUS
            ),
        )
        _update, merged, _recorder = _run(
            {"static": _refused("static"), LONG_KEY: empty_composed, "triage": no_report}
        )

        assert {name: len(isr.claims) for name, isr in merged.items()} == {
            "static": 9,
            LONG_KEY: 23,
            "triage": 13,
        }
        # What the judge is shown: the evidence summary built from the answers in force.
        shown = summarise(merged, [])
        for technique in ("T1027", "T1053.005", "T1218.011"):
            assert technique in shown

    def test_the_debate_names_each_analyst_with_its_real_claim_count(self) -> None:
        empty_composed = ("", AgentISR(agent_id=LONG_KEY, domain="static", claims=[]))
        _update, _merged, recorder = _run(
            {"static": _refused("static"), LONG_KEY: empty_composed, "triage": _refused("triage")}
        )

        texts = {message["speaker"]: message["text"] for message in recorder.said()}
        assert texts[LONG_KEY].startswith("23 evidence-backed claims from the Reverser (Ghidra)")
        assert "***" not in texts[LONG_KEY]
        assert "no claims produced" not in " ".join(texts.values())
        assert "The revision was not made (it failed: " in texts["static"]
        assert texts["static"].startswith("9 evidence-backed claims")
        assert "this answer stands" in texts["triage"]


class TestAnUnlabelledLongKey:
    def test_is_named_by_its_stage_not_published_as_a_masked_key(self) -> None:
        empty_composed = ("", AgentISR(agent_id=LONG_KEY, domain="static", claims=[]))
        _update, _merged, recorder = _run(
            {"static": _refused("static"), LONG_KEY: empty_composed, "triage": _refused("triage")},
            unlabelled=True,
        )
        texts = {message["speaker"]: message["text"] for message in recorder.said()}
        headline = texts[LONG_KEY].split(" Leading:")[0]
        assert LONG_KEY not in headline
        assert headline == "23 evidence-backed claims from analyst 2 of 3 in the analysis stage."
        # A short key is still the name.
        assert texts["static"].startswith("9 evidence-backed claims from the static layer")


class TestTwoUnlabelledLongKeysInOneStage:
    def test_are_never_named_alike(self) -> None:
        from types import SimpleNamespace

        from maljan.pipeline.nodes import spoken_name

        first, second = "all_tools_reverser_ghidra", "all_tools_reverser_binja_"
        container = MagicMock()
        container.config.agents.definitions = {}
        stage = SimpleNamespace(key="reversing", agents=[first, second])
        names = {spoken_name(container, key, stage) for key in (first, second)}
        assert names == {"reversing analyst 1 of 2", "reversing analyst 2 of 2"}
        alone = SimpleNamespace(key="reversing", agents=[first])
        assert spoken_name(container, first, alone) == "reversing analyst"

    def test_the_debate_line_says_the_stage_as_a_place(self) -> None:
        from types import SimpleNamespace

        from maljan.pipeline.events import summarize_claims
        from maljan.pipeline.nodes import claims_source

        key = "all_tools_reverser_ghidra"
        container = MagicMock()
        container.config.agents.definitions = {}
        alone = SimpleNamespace(key="reversing", agents=[key])
        claims = [ClaimEvidence(claim="one", evidence_ref="[ev_0001]", confidence=0.5)]
        line = summarize_claims(
            claims, speaker="reversing analyst", source=claims_source(container, key, alone)
        )
        assert (
            line == "1 evidence-backed claim from the analyst in the reversing stage. Leading: one"
        )


class TestARevisionThatWasMade:
    def test_replaces_the_first_answer_even_with_fewer_claims(self) -> None:
        made = ("CLAIM: revised\n", _first("static", "T1106", 2))
        empty_composed = ("", AgentISR(agent_id=LONG_KEY, domain="static", claims=[]))
        _update, merged, _recorder = _run(
            {"static": made, LONG_KEY: empty_composed, "triage": made}
        )
        assert len(merged["static"].claims) == 2
        assert merged["static"].claims[0].technique_id == "T1106"
