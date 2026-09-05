"""The generic analyst, against a fake LLM.

Four properties, and they are the whole class: it sends its resolved prompt,
it revises through the shared framing, its ISRs carry its own key as the
domain, and a broken tool never costs the job an analyst.
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.tools import StructuredTool

from maljan.agents.composition import ResolvedAgent
from maljan.agents.configurable_analyst import ConfigurableAnalyst


class _Recording(FakeMessagesListChatModel):
    seen: list[list[dict[str, str]]] = []

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs):  # type: ignore[no-untyped-def]
        type(self).seen.append([{"type": m.type, "content": str(m.content)} for m in messages])
        return super()._generate(messages, stop, run_manager, **kwargs)


_ISR_TEXT = "CLAIM: found it\nEVIDENCE: string at 0x40\nCONFIDENCE: 0.7\nTECHNIQUE: T1027\n---\n"


def _llm(text: str = _ISR_TEXT) -> _Recording:
    _Recording.seen = []
    return _Recording(responses=[AIMessage(content=text)])


def _resolved(
    llm: Any, tools: list[Any] | None = None, reasons: tuple[str, ...] = ()
) -> ResolvedAgent:
    return ResolvedAgent(
        key="strings",
        role="generic",
        prompt="PROMPT-MARKER",
        tools=tools or [],
        static_provider_id="ghidra",
        llm=llm,
        degradation_reasons=reasons,
    )


def _agent(**over: Any) -> ConfigurableAnalyst:
    llm = over.pop("llm", None) or _llm()
    resolved = over.pop("resolved", None) or _resolved(llm, **over)
    return ConfigurableAnalyst("strings", resolved, llm)


def test_analyze_sends_the_resolved_prompt_and_the_data():
    agent = _agent()
    text = agent.analyze("EVIDENCE-BLOB")
    assert "found it" in text
    system, human = _Recording.seen[-1]
    assert system["content"] == "PROMPT-MARKER"
    assert human["content"] == "EVIDENCE-BLOB"


def test_revise_uses_the_shared_revision_framing():
    from maljan.agents.base_agent import revision_messages

    agent = _agent()
    agent.revise("RAW", "OWN", {"static": "S"}, "FEEDBACK")
    expected = revision_messages("PROMPT-MARKER", "RAW", "OWN", {"static": "S"}, "FEEDBACK")
    assert [m["content"] for m in _Recording.seen[-1]] == [text for _, text in expected]


def test_the_isr_domain_is_the_definition_key_not_a_guessed_role():
    agent = _agent()
    isr = agent.analyze_isr("EVIDENCE-BLOB")
    assert isr.domain == "strings"
    assert isr.agent_id == "strings"
    assert isr.claims and isr.claims[0].technique_id == "T1027"


def test_revise_isr_returns_the_text_and_an_isr_of_the_right_round():
    agent = _agent()
    text, isr = agent.revise_isr("RAW", "OWN", {}, "F", revision_round=2)
    assert "found it" in text
    assert isr.revision_round == 2 and isr.domain == "strings"


def test_the_isr_path_asks_for_the_structured_shape():
    agent = _agent()
    agent.analyze_isr("EVIDENCE-BLOB")
    human = _Recording.seen[-1][1]["content"]
    assert "CLAIM:" in human and "EVIDENCE:" in human and "TECHNIQUE:" in human
    assert "EVIDENCE-BLOB" in human


def test_a_resolution_degradation_is_carried_and_never_raised():
    agent = _agent(reasons=("agent tool 'mine.nope' unavailable",))
    assert agent.degradation_reasons == ["agent tool 'mine.nope' unavailable"]
    assert agent.analyze("data")


def test_a_tool_that_explodes_is_recorded_and_the_loop_still_answers(monkeypatch):
    """A custom analyst never fails a job — the rule B applies to custom servers."""

    def _boom() -> str:
        raise RuntimeError("tool is broken")

    tool = StructuredTool.from_function(func=_boom, name="boom", description="boom")
    agent = _agent(tools=[tool])

    def _explode(prompt_messages: list) -> str:
        raise RuntimeError("tool is broken")

    monkeypatch.setattr(agent, "execute_tool_loop", _explode)
    text = agent.analyze("data")
    assert text.startswith("[WARN]")
    assert any("tool is broken" in r for r in agent.degradation_reasons)


def test_a_tool_failure_still_produces_a_zero_claim_isr_rather_than_an_exception(monkeypatch):
    agent = _agent()

    def _explode(prompt_messages: list) -> str:
        raise RuntimeError("llm is down")

    monkeypatch.setattr(agent, "execute_tool_loop", _explode)
    isr = agent.analyze_isr("data")
    assert isr.domain == "strings" and isr.claims == []


def test_the_agent_reports_its_resolved_tools_without_re_resolving(monkeypatch):
    tool = StructuredTool.from_function(func=lambda: "x", name="grep", description="grep")
    agent = _agent(tools=[tool])
    assert [t.name for t in agent.tools] == ["grep"]
    agent._initialize_mcp_client()
    assert [t.name for t in agent.tools] == ["grep"]


def test_the_name_is_the_definition_key():
    assert _agent().name == "strings"


def test_a_genuine_answer_starting_with_warn_is_not_mistaken_for_a_degradation():
    """The degradation signal is explicit, not a sniffed text prefix.

    An operator's prompt could easily make the model open its answer with the
    word "WARN" — a caution about a false positive, say. That is real analysis
    and must not be discarded to a zero-claim ISR just because it starts with
    the same words the loop's own failure report uses.
    """
    text = "[WARN] found it\n" + _ISR_TEXT
    agent = _agent(llm=_llm(text))
    isr = agent.analyze_isr("EVIDENCE-BLOB")
    assert isr.claims and isr.claims[0].technique_id == "T1027"
    assert agent.degradation_reasons == []
