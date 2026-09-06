"""The shared revision framing, examined directly.

``test_revision_prompt_golden.py`` proves the network analyst still sends the
same bytes. This proves the helper it now sends them through behaves the way
``ConfigurableAnalyst`` will rely on: the system prompt passes through
untouched on the text path and gains the negotiation framing on the ISR path,
the peer section is labelled differently on each, and an agent with no peers
says so rather than sending an empty block.
"""

from __future__ import annotations

from maljan.agents.base_agent import (
    _REVISION_ISR_FRAMING,
    prompt_to_messages,
    revision_messages,
)

PEERS = {"static": "S-TEXT", "dynamic": "D-TEXT"}


def _one(isr: bool) -> tuple[str, str]:
    messages = revision_messages(
        "SYSTEM-TEXT", "RAW", "OWN", PEERS, "FEEDBACK", isr=isr, revision_round=3
    )
    assert [role for role, _ in messages] == ["system", "human"]
    return messages[0][1], messages[1][1]


def test_the_text_path_passes_the_system_prompt_through_untouched():
    system, _ = _one(isr=False)
    assert system == "SYSTEM-TEXT"


def test_the_isr_path_appends_the_negotiation_framing():
    system, _ = _one(isr=True)
    assert system == "SYSTEM-TEXT" + "\n\n" + _REVISION_ISR_FRAMING
    assert "DISPUTES: NONE" in _REVISION_ISR_FRAMING


def test_the_text_path_labels_peers_as_analyst_reports():
    _, human = _one(isr=False)
    assert "STATIC ANALYST REPORT:\nS-TEXT" in human
    assert "DYNAMIC ANALYST REPORT:\nD-TEXT" in human
    assert "PEER ANALYST REPORTS:" in human
    assert "MEDIATOR CONTRADICTIONS:\nFEEDBACK" in human
    assert human.endswith("Revise your analysis addressing the contradictions above.")


def test_the_isr_path_labels_peers_as_reports_and_asks_for_disputes():
    _, human = _one(isr=True)
    assert "STATIC REPORT:\nS-TEXT" in human
    assert "PEER REPORTS:" in human
    assert "MEDIATOR FEEDBACK:\nFEEDBACK" in human
    assert "DISPUTES:" in human


def test_both_paths_carry_the_raw_data_and_the_agents_own_report():
    for isr in (False, True):
        _, human = _one(isr)
        assert "OWN" in human and "RAW" in human


def test_an_agent_with_no_peers_is_told_so():
    for isr in (False, True):
        messages = revision_messages("S", "RAW", "OWN", {}, "F", isr=isr)
        assert "No peer reports available." in messages[1][1]


def test_prompt_to_messages_builds_the_two_message_types_without_a_template():
    """Braces in the *content* must not be read as template variables."""
    messages = prompt_to_messages([("system", "S {json}"), ("human", 'H {"a": 1}')])
    assert [m.type for m in messages] == ["system", "human"]
    assert messages[0].content == "S {json}"
    assert messages[1].content == 'H {"a": 1}'


def test_prompt_to_messages_ignores_a_role_it_does_not_know():
    assert prompt_to_messages([("assistant", "x"), ("human", "y")]) == prompt_to_messages(
        [("human", "y")]
    )
