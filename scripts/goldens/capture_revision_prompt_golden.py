"""Pin the exact messages the network analyst's two revision paths send.

Task 4 extracts the revision framing out of ``NetworkAnalyst`` into
``BaseAnalyst.revision_messages`` so ``ConfigurableAnalyst`` can call the same
function. That extraction is a refactor only if the model receives the same
bytes afterwards, so the bytes are recorded here first, from a fake LLM that
answers nothing and remembers everything.

Run: ``uv run python scripts/goldens/capture_revision_prompt_golden.py``
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage, BaseMessage

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "revision_prompt_network.json"

# Deliberately boring inputs: the point is the framing around them, and a value
# with a brace or a newline in it would only test the template engine.
INPUTS = {
    "original_data": "RAW-DATA-MARKER",
    "own_report": "OWN-REPORT-MARKER",
    "peer_reports": {"static": "STATIC-MARKER", "dynamic": "DYNAMIC-MARKER"},
    "mediator_feedback": "MEDIATOR-MARKER",
}


class RecordingLLM(FakeMessagesListChatModel):
    """A chat model that answers a constant and keeps every message it saw."""

    seen: list[list[dict[str, str]]] = []

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs):  # type: ignore[no-untyped-def]
        type(self).seen.append([{"type": m.type, "content": str(m.content)} for m in messages])
        return super()._generate(messages, stop, run_manager, **kwargs)


def revision_shape() -> dict[str, Any]:
    from maljan.agents.network_analyst import NetworkAnalyst

    llm = RecordingLLM(responses=[AIMessage(content="CLAIM: x\nEVIDENCE: y\n---\n")])
    agent = NetworkAnalyst(llm=llm, name="network")

    RecordingLLM.seen = []
    agent.revise(
        INPUTS["original_data"],
        INPUTS["own_report"],
        INPUTS["peer_reports"],
        INPUTS["mediator_feedback"],
    )
    revise = RecordingLLM.seen[-1]

    RecordingLLM.seen = []
    agent.revise_isr(
        INPUTS["original_data"],
        INPUTS["own_report"],
        INPUTS["peer_reports"],
        INPUTS["mediator_feedback"],
        revision_round=2,
    )
    revise_isr = RecordingLLM.seen[-1]

    return {"inputs": INPUTS, "revise": revise, "revise_isr": revise_isr}


def main() -> None:
    GOLDEN.parent.mkdir(parents=True, exist_ok=True)
    # No sort_keys: "inputs.peer_reports" is order-sensitive — the two
    # revision paths join peer reports in dict-iteration order, and a golden
    # that alphabetized the nested dict would replay a different order than
    # the one that produced "revise" and "revise_isr" below.
    GOLDEN.write_text(json.dumps(revision_shape(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {GOLDEN}")


if __name__ == "__main__":
    main()
