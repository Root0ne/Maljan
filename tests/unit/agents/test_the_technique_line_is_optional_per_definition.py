"""An agent definition may turn the ATT&CK technique line off; on is what it always was.

``AgentDefinition.attck_techniques`` defaults to on, and on is byte for byte
the prompt every definition was sent before the field existed: the texts are
pinned here as literals, over every shipped definition. Off leaves the request
out of every text that asks a configurable agent for one: its ISR instruction,
its negotiation round, a delegated ask, the validation questions, a provider's
ATT&CK focus sentence and priority follow-up, and the view and tier pilot.
The parser is the same either way: a claim with no TECHNIQUE line raises no
question, and a TECHNIQUE line the agent writes anyway is read and checked as
any other.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage, BaseMessage
from pydantic import ValidationError

from maljan.agents.base_agent import revision_messages
from maljan.agents.composition import ResolvedAgent
from maljan.agents.configurable_analyst import ConfigurableAnalyst
from maljan.core.config import (
    ATTCK_OPT_OUT_RULE,
    PROMPT_ROLES,
    AgentDefinition,
    _builtin_definitions,
)
from maljan.pipeline.validation import TECHNIQUE_LINE_UNREAD_CODE, parse_violations

# The ISR instruction and the negotiation round's closing as dev sent them.
DEV_ISR_INSTRUCTION = (
    "Return a structured list of findings. For each finding state: the claim, "
    "the exact artifact reference, your confidence (0.0-1.0), and the MITRE "
    "ATT&CK technique ID.\n\n"
    "Format each finding as:\n"
    "CLAIM: <claim text>\n"
    "EVIDENCE: <artifact reference, naming the tool result you read it from, "
    "for example [ev_0002]>\n"
    "CONFIDENCE: <float>\n"
    "TECHNIQUE: <T-ID, several separated by commas, or NONE>\n"
    "---\n"
    "\n"
)
DEV_REVISION_CLOSING = (
    "Format your response as structured claims (CLAIM/EVIDENCE/CONFIDENCE/TECHNIQUE)\n"
    "followed by a DISPUTES section listing peer claims you reject.\n"
    "Example:\n"
    "CLAIM: ...\nEVIDENCE: ...\nCONFIDENCE: 0.8\nTECHNIQUE: T1071\n---\n"
    "DISPUTES:\n- Static analyst says no C2 strings but PCAP shows beaconing.\n"
)


class _Recording(FakeMessagesListChatModel):
    seen: list[list[dict[str, str]]] = []

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs):  # type: ignore[no-untyped-def]
        type(self).seen.append([{"type": m.type, "content": str(m.content)} for m in messages])
        return super()._generate(messages, stop, run_manager, **kwargs)


def _agent(text: str, *, techniques: bool, role: str = "generic") -> ConfigurableAnalyst:
    _Recording.seen = []
    llm = _Recording(responses=[AIMessage(content=text)] * 2)
    resolved = ResolvedAgent(
        key="checker",
        role=role,
        prompt="PROMPT-MARKER",
        tools=[],
        static_provider_id="ghidra",
        llm=llm,
        attck_techniques=techniques,
    )
    return ConfigurableAnalyst("checker", resolved, llm)


def _human() -> str:
    return next(m["content"] for m in _Recording.seen[-1] if m["type"] == "human")


_NO_LINE = "CLAIM: the config names a host\nEVIDENCE: [ev_0002]\nCONFIDENCE: 0.7\n---\n"


class TestOnIsTheDevPrompt:
    @pytest.mark.parametrize("key", sorted(_builtin_definitions()))
    def test_every_shipped_definition_keeps_it_on_and_dumps_as_before(self, key: str) -> None:
        definition = _builtin_definitions()[key]
        assert definition.attck_techniques is True
        assert "attck_techniques" not in definition.model_dump()
        assert "attck_techniques" not in definition.model_dump(mode="json")

    @pytest.mark.parametrize("key", sorted(_builtin_definitions()))
    def test_every_shipped_definition_is_sent_the_dev_isr_instruction(self, key: str) -> None:
        definition = _builtin_definitions()[key]
        agent = _agent(_NO_LINE, techniques=definition.attck_techniques, role=definition.role)
        agent.analyze_isr("DATA")
        assert _human().startswith(DEV_ISR_INSTRUCTION)

    @pytest.mark.parametrize("key", sorted(_builtin_definitions()))
    def test_every_shipped_definition_revises_with_the_dev_closing(self, key: str) -> None:
        definition = _builtin_definitions()[key]
        agent = _agent(_NO_LINE, techniques=definition.attck_techniques, role=definition.role)
        agent.revise_isr("DATA", "OWN", {"peer": "P"}, "FEEDBACK")
        assert _human().endswith("RAW DATA:\nDATA\n\n" + DEV_REVISION_CLOSING)

    def test_the_revision_default_is_the_dev_text(self) -> None:
        sent = revision_messages("SYS", "DATA", "OWN", {"peer": "P"}, "FB", isr=True)
        assert sent[1][1] == (
            "YOUR ORIGINAL REPORT:\nOWN\n\nPEER REPORTS:\nPEER REPORT:\nP\n\n"
            "MEDIATOR FEEDBACK:\nFB\n\nRAW DATA:\nDATA\n\n" + DEV_REVISION_CLOSING
        )


class TestTheField:
    def test_a_stored_definition_without_it_loads_on_and_dumps_unchanged(self) -> None:
        stored = {
            "role": "generic",
            "label": "Checker",
            "prompt": "Check the configuration.",
            "tools": [],
            "static_provider": None,
            "enabled": True,
            "data_sources": [],
            "max_steps": None,
            "timeout_seconds": None,
            "tab": None,
        }
        definition = AgentDefinition.model_validate(stored)
        assert definition.attck_techniques is True
        assert definition.model_dump(mode="json") == stored

    def test_off_on_a_prompt_role_round_trips(self) -> None:
        for role in PROMPT_ROLES:
            definition = AgentDefinition(role=role, prompt="P", attck_techniques=False)
            dumped = definition.model_dump(mode="json")
            assert dumped["attck_techniques"] is False
            assert AgentDefinition.model_validate(dumped).attck_techniques is False

    @pytest.mark.parametrize("role", ["static", "dynamic", "network", "judge", "report"])
    def test_off_on_a_built_in_role_is_refused_by_name(self, role: str) -> None:
        with pytest.raises(ValidationError, match="attck_techniques can be turned off") as err:
            AgentDefinition(role=role, attck_techniques=False)
        assert err.value.errors()[0]["loc"] == ("attck_techniques",)
        assert ATTCK_OPT_OUT_RULE in str(err.value)


class TestOffLeavesTheRequestOut:
    def test_the_isr_instruction_asks_for_no_technique(self) -> None:
        _agent(_NO_LINE, techniques=False).analyze_isr("DATA")
        human = _human()
        assert "TECHNIQUE" not in human
        assert "ATT&CK" not in human
        assert "CLAIM: <claim text>" in human
        assert "CONFIDENCE: <float>" in human

    def test_the_negotiation_round_asks_for_no_technique(self) -> None:
        _agent(_NO_LINE, techniques=False).revise_isr("DATA", "OWN", {}, "FB")
        assert "TECHNIQUE" not in _human()


class TestTheParserIsTheSame:
    def test_a_claim_with_no_technique_line_raises_no_question(self) -> None:
        isr = _agent(_NO_LINE, techniques=False).analyze_isr("DATA")
        assert len(isr.claims) == 1
        assert isr.claims[0].technique_id is None
        assert parse_violations(isr) == []

    def test_a_technique_line_written_anyway_is_read(self) -> None:
        text = _NO_LINE.replace("---\n", "TECHNIQUE: T1027\n---\n")
        isr = _agent(text, techniques=False).analyze_isr("DATA")
        assert [c.technique_id for c in isr.claims] == ["T1027"]

    def test_a_technique_line_written_anyway_is_checked(self) -> None:
        text = _NO_LINE.replace("---\n", "TECHNIQUE: maybe T1027 or T1055\n---\n")
        isr = _agent(text, techniques=False).analyze_isr("DATA")
        codes = [v.code for v in parse_violations(isr)]
        assert TECHNIQUE_LINE_UNREAD_CODE in codes


# The validation texts as dev sent them, pinned whole.
DEV_CLOSING = (
    "Fix them and write your whole answer again in the format it is read in: every claim "
    "as its own block of CLAIM:, EVIDENCE:, CONFIDENCE: and TECHNIQUE: lines, the blocks "
    "separated by a line of three dashes (---), then your fenced maljan-findings block if "
    "your answer had one. Only CLAIM blocks are read as claims: a claim written another "
    "way, or left out, is not in the answer."
)
DEV_CLOSING_BY_NUMBER = (
    "Fix them by writing again only the claims you change. Your claims are numbered in the "
    "order you wrote them, counted from 1: write each claim you change under its number "
    "(CLAIM 7:) as its own block of CLAIM, EVIDENCE:, CONFIDENCE: and TECHNIQUE: lines, the "
    "blocks separated by a line of three dashes (---), and a new claim under a number your "
    "answer did not use. A claim you do not write again stays in your answer as you wrote "
    "it. To take a claim out, write a line WITHDRAW CLAIM <number>: <reason>. Your fenced "
    "maljan-findings block is kept the same way by each finding's title: write it with only "
    'the findings you change or add, and a line WITHDRAW FINDING "<title>": <reason> takes '
    "one out; a finding written under a new title is a new finding. Only CLAIM blocks are "
    "read as claims."
)
DEV_UNPARSED = (
    "Your answer has no CLAIM block that can be read, so it carries no claim and "
    "is kept as prose. Restate each finding as a block, with the confidence you "
    "hold it at:\n"
    "CLAIM: <claim text>\n"
    "EVIDENCE: <artifact reference, naming the tool result you read it from, "
    "for example [ev_0002]>\n"
    "CONFIDENCE: <0.0-1.0>\n"
    "TECHNIQUE: <T-ID, several separated by commas, or NONE>\n"
    "---\n"
    "A finding you cannot put a confidence on stays in your prose."
)
DEV_CUT = (
    "Your previous answer stopped at the output limit of 512 tokens while you were still "
    "reasoning, before any of its text was written. Any reasoning you write counts against "
    "the same limit. Write the whole answer again so that it ends well inside 512 tokens: "
    "the claims the evidence supports best, each written once, each one sentence with its "
    "EVIDENCE, CONFIDENCE and TECHNIQUE lines, and nothing between the blocks."
)
DEV_REPEATED = (
    "Your previous answer ran to 7 characters and began 7 CLAIM block(s), 7 of them distinct: "
    "0 repeat a claim already written, more than the 7 allowed. It was ended while it "
    "streamed, once its repeats passed that margin; what it wrote up to there is kept. It "
    "also stopped at the output limit of 900 tokens before it ended: the whole answer has to "
    "end well inside that limit, and any reasoning you write counts against it. It is shown "
    "above only up to CLAIM block 7, the first that repeats an earlier one; the rest is not "
    "shown to you again. Write the whole answer again: the claims shown above and any other "
    "the evidence supports, each written once, each one sentence with its EVIDENCE, "
    "CONFIDENCE and TECHNIQUE lines, and nothing between the blocks."
)


def _repeated() -> Any:
    from maljan.pipeline.validation import ClaimsRepeated

    return ClaimsRepeated(
        begun=7, distinct=7, margin=7, chars=7, before="CLAIM: a\nEVIDENCE: b\n", first_repeat=7
    )


def _prose_isr() -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(
        unparsed_answer="prose",
        answer_text="prose",
        claims=[],
        blocks_without_confidence=0,
        claims_under_disputes=0,
        confidence_unreadable=[],
    )


class TestTheValidationQuestionsFollowTheSwitch:
    def test_on_every_question_is_the_dev_text(self) -> None:
        from maljan.pipeline import validation as v

        assert v.analyst_feedback_closing(whole=True) == DEV_CLOSING
        assert v.analyst_feedback_closing(whole=False) == DEV_CLOSING_BY_NUMBER
        assert v.ANALYST_FEEDBACK_CLOSING == DEV_CLOSING
        assert v.ANALYST_FEEDBACK_CLOSING_BY_NUMBER == DEV_CLOSING_BY_NUMBER
        assert v.whole_answer_after_retry_question("why") == (
            "Your retry could not be merged into your answer by claim number: why. "
            "Your answer is now read whole. " + DEV_CLOSING
        )
        assert [x.message for x in v.parse_violations(_prose_isr())] == [DEV_UNPARSED]
        assert v.analyst_cut_violation(512).message == DEV_CUT
        repeated = v.analyst_repeated_violation(_repeated(), cut=900, ended=True)
        assert repeated.message == DEV_REPEATED

    def test_off_every_question_names_the_block_without_its_technique_line(self) -> None:
        from maljan.pipeline import validation as v

        off = {
            "closing": v.analyst_feedback_closing(whole=True, techniques=False),
            "by number": v.analyst_feedback_closing(whole=False, techniques=False),
            "whole": v.whole_answer_after_retry_question("why", techniques=False),
            "unparsed": v.parse_violations(_prose_isr(), techniques=False)[0].message,
            "cut": v.analyst_cut_violation(512, techniques=False).message,
            "repeated": v.analyst_repeated_violation(
                _repeated(), cut=900, ended=True, techniques=False
            ).message,
        }
        for name, text in off.items():
            assert "technique" not in text.lower(), name
        # The same sentences otherwise, so the two never drift apart.
        assert off["closing"] == DEV_CLOSING.replace(
            "CLAIM:, EVIDENCE:, CONFIDENCE: and TECHNIQUE: lines",
            "CLAIM:, EVIDENCE: and CONFIDENCE: lines",
        )
        assert off["by number"] == DEV_CLOSING_BY_NUMBER.replace(
            "CLAIM, EVIDENCE:, CONFIDENCE: and TECHNIQUE: lines",
            "CLAIM, EVIDENCE: and CONFIDENCE: lines",
        )
        assert off["whole"].endswith(off["closing"])
        assert off["unparsed"] == DEV_UNPARSED.replace(
            "TECHNIQUE: <T-ID, several separated by commas, or NONE>\n", ""
        )
        for name, dev in (("cut", DEV_CUT), ("repeated", DEV_REPEATED)):
            assert off[name] == dev.replace(
                "EVIDENCE, CONFIDENCE and TECHNIQUE lines", "EVIDENCE and CONFIDENCE lines"
            ), name

    @pytest.mark.parametrize("techniques", [True, False])
    def test_an_agent_s_retry_is_asked_in_its_own_claim_format(self, techniques: bool) -> None:
        prose = "I read the configuration and found nothing to report."
        agent = _agent(prose, techniques=techniques)
        _Recording.seen = []
        agent.llm = _Recording(responses=[AIMessage(content=prose), AIMessage(content=_NO_LINE)])
        isr = agent.safe_analyze_isr("DATA")
        assert len(_Recording.seen) >= 2
        retry = " ".join(m["content"] for m in _Recording.seen[1] if m["type"] == "human")
        if techniques:
            assert DEV_UNPARSED in retry
            assert DEV_CLOSING in retry or DEV_CLOSING_BY_NUMBER in retry
        else:
            sent = " ".join(m["content"] for call in _Recording.seen for m in call)
            assert "TECHNIQUE" not in sent
            assert "ATT&CK" not in sent
            assert "CONFIDENCE: <0.0-1.0>" in retry
        assert [c.claim for c in isr.claims] == ["the config names a host"]


class TestTheResolverCarriesTheSwitch:
    @staticmethod
    def _settings(**over: Any) -> Any:
        from maljan.core.config import Settings

        checker = {"role": "generic", "prompt": "Check the configuration.", **over}
        return Settings(
            _env_file=None,
            agents={
                "definitions": {"checker": checker},
                "profiles": {"one": {"analysts": ["checker"]}},
                "profile": "one",
            },
        )

    @pytest.mark.parametrize("techniques", [True, False])
    def test_both_resolvers_carry_the_definition_s_switch(self, techniques: bool) -> None:
        import asyncio

        from maljan.agents.composition import aresolve_agent, resolve_agent
        from tests.unit.agents.test_composition import _Container

        cfg = self._settings(attck_techniques=techniques)
        assert resolve_agent("checker", _Container(cfg)).attck_techniques is techniques
        resolved = asyncio.run(aresolve_agent("checker", _Container(cfg)))
        assert resolved.attck_techniques is techniques
        agent = ConfigurableAnalyst("checker", resolved, None)  # type: ignore[arg-type]
        assert agent.asks_for_techniques() is techniques

    def test_a_provider_s_attck_focus_sentence_is_left_out_when_off(self) -> None:
        from maljan.agents.composition import resolve_agent
        from maljan.providers.base import ATTCK_FOCUS, CLAIM_ARTIFACT_CITATION, CLAIM_CITATION
        from tests.unit.agents.test_composition import _Container, _Provider

        class _Citing(_Provider):
            def prompt_fragment(self) -> str:
                return "R2 LEAD. " + CLAIM_CITATION + "\n\nR2 WORKFLOW."

        reading = {"static_provider": "r2", "tools": [{"kind": "provider"}]}
        on = resolve_agent("checker", _Container(self._settings(**reading), provider=_Citing()))
        off = resolve_agent(
            "checker",
            _Container(self._settings(**reading, attck_techniques=False), provider=_Citing()),
        )
        assert CLAIM_CITATION in on.prompt
        assert "ATT&CK" not in off.prompt
        assert CLAIM_ARTIFACT_CITATION + "\n\nR2 WORKFLOW." in off.prompt
        assert off.prompt == on.prompt.replace(" " + ATTCK_FOCUS, "")


class TestTheProviderTextsLoseOnlyTheirAttckClause:
    def test_the_split_constants_join_into_the_dev_texts(self) -> None:
        from maljan.analysis.sink_reachability import FOLLOW_UP
        from maljan.providers.base import CLAIM_CITATION
        from maljan.providers.static.ghidra.call_graph import PRIORITY_FOLLOW_UP

        assert CLAIM_CITATION == (
            "For EVERY claim you make, you MUST cite a concrete artifact: a function name, "
            "string offset (.data+0xNN), API import, or hex pattern. "
            "Focus on MITRE ATT&CK: T1027 (Obfuscation), T1106 (Native API), "
            "T1055 (Process Injection), T1140 (Deobfuscation)."
        )
        assert FOLLOW_UP == (
            "Read these functions first with the tools in your tool list. NOTE: reachable is NOT "
            "the same as data-connected — before asserting a 'capability reached' claim, confirm "
            "the data path (forward from the source, or backward from the sink argument) and "
            "classify the terminal (caller-supplied / decoded-config / fixed constant) to pick "
            "the right ATT&CK technique.\n"
        )
        assert PRIORITY_FOLLOW_UP == (
            "Use decompile_function / get_function_callees on these first. NOTE: "
            "reachable is NOT the same as data-connected — before asserting a "
            "'capability reached' claim, confirm the data path with analyze_dataflow "
            "(forward from the source, or backward from the sink argument) and "
            "classify the terminal (caller-supplied / decoded-config / fixed "
            "constant) to pick the right ATT&CK technique.\n"
        )

    @pytest.mark.parametrize("techniques", [True, False])
    def test_the_priority_hint_follow_up_follows_the_switch(
        self, techniques: bool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        from langchain_core.tools import StructuredTool

        from maljan.agents.prompt_fragments import PROVIDER_FAMILY, stamp_source
        from maljan.analysis.sink_reachability import FOLLOW_UP
        from maljan.providers import base as provider_base
        from maljan.providers.static.ghidra.call_graph import PRIORITY_FOLLOW_UP

        def decompile() -> str:
            """Decompile."""
            return "x"

        agent = _agent(_NO_LINE, techniques=techniques)
        tool = StructuredTool.from_function(func=decompile, name="decompile", description="d")
        agent.tools = stamp_source([tool], PROVIDER_FAMILY)
        monkeypatch.setattr(agent, "_own_static_provider", lambda: None)
        head = json.dumps({"analysis_file_path": "/samples/s.bin"})
        for follow_up in (FOLLOW_UP, PRIORITY_FOLLOW_UP):
            hint = "PRIORITY FUNCTIONS:\n- f\n" + follow_up
            monkeypatch.setattr(provider_base, "prepare_sample", lambda *_a, _h=hint: _h)
            sent = agent._priority_hint(head)
            if techniques:
                assert sent == hint + "\n"
            else:
                assert "ATT&CK" not in sent
                assert sent == hint.replace(" to pick the right ATT&CK technique", "") + "\n"


class TestTheViewAndTierPilotFollowTheSwitch:
    def test_on_the_view_system_and_the_ladder_are_the_dev_texts(self) -> None:
        from maljan.agents import base_agent as b

        claim_format = DEV_ISR_INSTRUCTION[DEV_ISR_INSTRUCTION.index("Format each finding") : -1]
        assert b._VIEW_SYSTEM == (
            "You are an expert malware analyst examining one focused facet of a sample. "
            "Analyse ONLY the aspect named in the instruction; ignore everything else. "
            "For EVERY claim you MUST cite a concrete artifact (API/import, string, path, "
            "registry key, host/domain). DO NOT invent capabilities or technique IDs — if "
            "the evidence does not support a claim, omit it. Cite MITRE ATT&CK technique "
            "IDs in the form Txxxx or Txxxx.yyy only when the evidence supports them.\n"
            + claim_format
        )
        assert b._tier_specs(3) == b._TIER_SPECS
        assert b._tier_specs(5)[:3] == b._TIER_SPECS

    @pytest.mark.parametrize("techniques", [True, False])
    def test_an_agent_s_view_call_carries_its_own_claim_format(
        self, techniques: bool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import base_agent as b

        agent = _agent(_NO_LINE, techniques=techniques)
        sent: list[str] = []

        def capture(messages: list[Any], **_k: Any) -> str:
            sent.append(str(messages[0].content))
            return ""

        monkeypatch.setattr(agent, "ask_the_model", capture)
        agent._invoke_view("Focus on one facet.", "DATA", None)
        if techniques:
            assert sent == [b._VIEW_SYSTEM]
        else:
            assert sent == [b._VIEW_SYSTEM_WITHOUT_TECHNIQUES]
            assert "technique" not in sent[0].lower()

    @pytest.mark.parametrize("techniques", [True, False])
    def test_an_agent_s_tiers_follow_its_switch(
        self, techniques: bool, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import base_agent as b

        agent = _agent(_NO_LINE, techniques=techniques)
        asked: list[str] = []

        def capture(instruction: str, *_a: Any) -> str:
            asked.append(instruction)
            return ""

        monkeypatch.setattr(agent, "_invoke_view", capture)
        agent.analyze_isr_tiered("DATA", 3)
        if techniques:
            assert asked == [text for _key, text in b._TIER_SPECS]
        else:
            assert asked == [text for _key, text in b._TIER_SPECS_WITHOUT_TECHNIQUES]
            for text in asked:
                assert "ATT&CK" not in text and "technique" not in text.lower()
