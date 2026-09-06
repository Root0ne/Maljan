"""The network analyst's revision messages are frozen.

Both revision paths are about to be re-expressed through one shared helper
(``BaseAnalyst.revision_messages``, Task 4) so the configurable analyst can
send the same framing. The helper is a refactor only if the model receives
identical bytes, which is what this compares — against a fixture captured
from the pre-extraction code by ``scripts/goldens/capture_revision_prompt_golden.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage, BaseMessage

GOLDEN = (
    Path(__file__).resolve().parents[2] / "fixtures" / "golden" / "revision_prompt_network.json"
)


class _Recording(FakeMessagesListChatModel):
    seen: list[list[dict[str, str]]] = []

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs):  # type: ignore[no-untyped-def]
        type(self).seen.append([{"type": m.type, "content": str(m.content)} for m in messages])
        return super()._generate(messages, stop, run_manager, **kwargs)


def _agent() -> tuple:
    from maljan.agents.network_analyst import NetworkAnalyst

    llm = _Recording(responses=[AIMessage(content="CLAIM: x\nEVIDENCE: y\n---\n")])
    return NetworkAnalyst(llm=llm, name="network"), json.loads(GOLDEN.read_text(encoding="utf-8"))


def test_revise_sends_the_captured_messages():
    agent, golden = _agent()
    inputs = golden["inputs"]
    _Recording.seen = []
    agent.revise(
        inputs["original_data"],
        inputs["own_report"],
        inputs["peer_reports"],
        inputs["mediator_feedback"],
    )
    assert _Recording.seen[-1] == golden["revise"]


def test_revise_isr_sends_the_captured_messages():
    agent, golden = _agent()
    inputs = golden["inputs"]
    _Recording.seen = []
    agent.revise_isr(
        inputs["original_data"],
        inputs["own_report"],
        inputs["peer_reports"],
        inputs["mediator_feedback"],
        revision_round=2,
    )
    assert _Recording.seen[-1] == golden["revise_isr"]


def test_the_two_paths_are_genuinely_different_prompts():
    """A golden that accidentally captured one path twice would prove nothing."""
    _, golden = _agent()
    assert golden["revise"] != golden["revise_isr"]
    assert len(golden["revise"]) == 2 and len(golden["revise_isr"]) == 2
    assert golden["revise"][0]["type"] == "system"
    assert golden["revise"][1]["type"] == "human"


def test_every_input_marker_reaches_the_model():
    _, golden = _agent()
    body = golden["revise"][1]["content"] + golden["revise_isr"][1]["content"]
    for marker in ("RAW-DATA-MARKER", "OWN-REPORT-MARKER", "MEDIATOR-MARKER"):
        assert marker in body
    assert "STATIC-MARKER" in body and "DYNAMIC-MARKER" in body
