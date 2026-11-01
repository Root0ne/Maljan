"""Each technique id a conversation names carries its catalogue facts once, where the cache holds.

An analyst asked the knowledge tools for the name, tactics and parent of ids it
had already claimed: deterministic answers the platform holds. Every request
now states them (``agents.technique_facts``): a note at the end of the user
turn that closes each stretch of the conversation, for the ids named up to it
that nothing stated before. Checked here: which ids count as named, that each
is stated once across turns and beside a retry's own catalogue facts, how an id
the catalogue lacks is stated, that a conversation naming none is sent exactly
as before, that every request is the one before it plus new turns (so a
provider's prefix cache, a continued question's cached prefix and a replayed
thinking block's binding hold) on the OpenAI-compatible, DeepSeek and Anthropic
paths, and that a cleared tool answer keeps the facts it carried.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
    convert_to_openai_messages,
)
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import BaseAnalyst, frame_messages
from maljan.agents.technique_facts import (
    TECHNIQUE_FACTS_ATTACHED,
    TECHNIQUE_FACTS_TURN_LEAD,
    notes_kept_after_clearing,
    with_technique_facts,
)
from maljan.pipeline.run_state import is_run_state_block, without_run_state_tail
from maljan.pipeline.validation import TECHNIQUE_FACTS_LEAD

RUN_STATE = "sample: c\nbudget remaining: 3 model turns"


def _fact(tid: str) -> str:
    return f"- {tid} name of {tid}"


def _known(tid: str) -> bool:
    return tid != "T9999"


def _facts(messages: list[Any]) -> list[Any]:
    return with_technique_facts(messages, fact=_fact, known=_known)


def _note(*ids: str) -> str:
    return "\n".join([TECHNIQUE_FACTS_TURN_LEAD, *(_fact(t) for t in ids)])


def _stated(messages: list[Any]) -> list[str]:
    """Every id the platform's notes state, in order, repeats kept."""
    out: list[str] = []
    for message in messages:
        note = (message.response_metadata or {}).get(TECHNIQUE_FACTS_ATTACHED)
        if note:
            out.extend(line.split()[1] for line in note.split("\n")[1:])
    return out


def _call(index: int, text: str = "") -> AIMessage:
    return AIMessage(
        content=text, tool_calls=[{"name": "lookup", "args": {"what": "x"}, "id": f"c{index}"}]
    )


class TestWhatIsNamed:
    def test_a_model_turn_s_text_and_a_human_turn_name_ids(self) -> None:
        out = _facts(
            [
                SystemMessage(content="Write TECHNIQUE: T1001 lines."),
                HumanMessage(content="Your claim: TECHNIQUE: T1105"),
                _call(0, "CLAIM: it resolves APIs\nTECHNIQUE: T1027.007"),
                ToolMessage(content="[ev_0001]\nrule T1055 matched", tool_call_id="c0"),
            ]
        )
        assert out[0].content == "Write TECHNIQUE: T1001 lines."
        assert out[1].content == f"Your claim: TECHNIQUE: T1105\n\n{_note('T1105')}"
        assert out[3].content == f"[ev_0001]\nrule T1055 matched\n\n{_note('T1027.007')}"
        # The model's own turn is never written to.
        assert out[2].content == "CLAIM: it resolves APIs\nTECHNIQUE: T1027.007"

    def test_reasoning_tool_requests_tool_answers_and_lower_case_name_nothing(self) -> None:
        messages = [
            HumanMessage(content="Analyse t1105."),
            AIMessage(
                content=[
                    {"type": "thinking", "thinking": "maybe T1105", "signature": "s"},
                    {"type": "text", "text": "Looking."},
                ],
                tool_calls=[
                    {"name": "attck_lookup", "args": {"technique_id": "T1622"}, "id": "c0"}
                ],
            ),
            ToolMessage(content="T1622 Debugger Evasion", tool_call_id="c0"),
        ]
        out = _facts(messages)
        assert all(a is b for a, b in zip(out, messages, strict=True))

    def test_a_format_example_s_id_names_nothing(self) -> None:
        example = "Example:\nCLAIM: ...\nEVIDENCE: ...\nCONFIDENCE: 0.8\nTECHNIQUE: T1071\n---\n"
        messages = [HumanMessage(content=f"OWN REPORT\n\n{example}")]
        assert _facts(messages)[0] is messages[0]
        out = _facts([HumanMessage(content=f"CLAIM: it beacons\nTECHNIQUE: T1071\n{example}")])
        assert _stated(out) == ["T1071"]

    def test_an_id_no_catalogue_had_is_stated_only_where_the_model_wrote_it(self) -> None:
        out = _facts(
            [
                HumanMessage(content="A string of the sample: T9999 T1105"),
                _call(0, "TECHNIQUE: T9999"),
                ToolMessage(content="answer", tool_call_id="c0"),
            ]
        )
        assert _stated(out) == ["T1105", "T9999"]
        assert out[2].content.endswith(_note("T9999"))


class TestEachIdOnce:
    def test_an_id_named_again_is_not_stated_again(self) -> None:
        messages = [
            HumanMessage(content="Revise T1105."),
            _call(0, "T1105 stands; T1622 too"),
            ToolMessage(content="a", tool_call_id="c0"),
            _call(1, "T1622 and T1105 again"),
            ToolMessage(content="b", tool_call_id="c1"),
        ]
        out = _facts(messages)
        assert _stated(out) == ["T1105", "T1622"]
        assert out[4] is messages[4]

    def test_parallel_answers_carry_one_note_on_the_last(self) -> None:
        turn = AIMessage(
            content="T1105",
            tool_calls=[
                {"name": "lookup", "args": {}, "id": "a"},
                {"name": "lookup", "args": {}, "id": "b"},
            ],
        )
        messages = [
            HumanMessage(content="go"),
            turn,
            ToolMessage(content="1", tool_call_id="a"),
            ToolMessage(content="2", tool_call_id="b"),
        ]
        out = _facts(messages)
        assert out[2] is messages[2]
        assert out[3].content == f"2\n\n{_note('T1105')}"

    def test_a_retry_s_catalogue_facts_state_their_ids_and_name_none(self) -> None:
        retry = "\n".join(
            [
                "Claim 2 carries T1027.007.",
                TECHNIQUE_FACTS_LEAD,
                "- T1027.007 Dynamic API Resolution: a sub-technique of T1027 Obfuscated Files",
                "- T1055.999: not a technique of the catalogue; the catalogue's nearest ids: "
                "T1055, T1055.001",
                "Fix the claims.",
            ]
        )
        out = _facts([HumanMessage(content=retry)])
        # The ids the retry stated, its parents and its nearest ids are not stated again.
        assert _stated(out) == []
        out = _facts([HumanMessage(content=f"{retry}\nAlso T1622.")])
        assert _stated(out) == ["T1622"]

    def test_framing_twice_states_nothing_twice(self) -> None:
        messages = [
            SystemMessage(content="s"),
            HumanMessage(content="Revise T1105."),
            _call(0, "T1622"),
            ToolMessage(content="a", tool_call_id="c0"),
        ]
        with patch(
            "maljan.agents.base_agent.with_technique_facts",
            lambda m: with_technique_facts(m, fact=_fact, known=_known),
        ):
            once = frame_messages(messages, run_state=RUN_STATE)
            twice = frame_messages(once, run_state=RUN_STATE)
        assert [m.content for m in twice] == [m.content for m in once]
        assert _stated(twice) == ["T1105", "T1622"]


class TestTheCatalogueSaysIt:
    def test_a_technique_s_name_parent_tactics_and_card(self) -> None:
        out = with_technique_facts(
            [HumanMessage(content="TECHNIQUE: T1027.007"), _call(0, "and T1105")]
        )
        note = str(out[0].content).split("\n\n", 1)[1]
        assert note.startswith(TECHNIQUE_FACTS_TURN_LEAD)
        assert "- T1027.007 Dynamic API Resolution: a sub-technique of T1027" in note
        assert "tactics: " in note

    def test_an_id_the_catalogue_lacks_is_said_to_be_none_of_its_techniques(self) -> None:
        out = with_technique_facts(
            [
                HumanMessage(content="go"),
                _call(0, "TECHNIQUE: T9999"),
                ToolMessage("a", tool_call_id="c0"),
            ]
        )
        assert "- T9999: not a technique of the catalogue" in str(out[2].content)


class TestAConversationNamingNoneIsSentAsBefore:
    def test_no_turn_changes(self) -> None:
        messages = [
            SystemMessage(content="s"),
            HumanMessage(content="Analyse the sample."),
            _call(0, "Reading the imports."),
            ToolMessage(content="[ev_0001]\nkernel32.dll", tool_call_id="c0"),
        ]
        out = with_technique_facts(messages)
        assert all(a is b for a, b in zip(out, messages, strict=True))

    def test_a_loop_s_requests_are_dev_s(self) -> None:
        plain: dict[str, Any] = {"texts": ["", "Reading.", "Done."], "answer": "No id."}
        seen = _loop(**plain, task="Analyse.")
        with patch("maljan.agents.base_agent.with_technique_facts", lambda m: list(m)):
            before = _loop(**plain, task="Analyse.")
        assert len(seen) == 5
        assert [_wire(r) for r in seen] == [_wire(r) for r in before]


# ── The loop, on the wire ─────────────────────────────────────────────────


class _What(BaseModel):
    what: str = ""


def _lookup_tool() -> StructuredTool:
    return StructuredTool.from_function(
        func=lambda what="": f"answer for {what}",
        name="lookup",
        description="Look it up.",
        args_schema=_What,
    )


class _Scripted(BaseChatModel):
    """Writes ``texts[n]`` beside its n-th tool call, then ``answer``; records requests."""

    texts: list = []
    answer: str = ""
    seen: list = []

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        sent = list(messages)
        self.seen.append(sent)
        made = sum(1 for m in sent if isinstance(m, AIMessage) and m.tool_calls)
        if made < len(self.texts):
            turn = AIMessage(
                content=self.texts[made],
                tool_calls=[{"name": "lookup", "args": {"what": f"w{made}"}, "id": f"c{made}"}],
            )
        else:
            turn = AIMessage(content=self.answer)
        return ChatResult(generations=[ChatGeneration(message=turn)])

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


REPORT = "CLAIM: it fetches a file\nEVIDENCE: ev_0002\nCONFIDENCE: 0.6\nTECHNIQUE: T1105\n"
NAMING = ["", "It may be T1105 or T1071.001.", "T1622 too, and T1105 again."]


def _loop(
    texts: list[str] = NAMING, answer: str = REPORT, task: str = "Revise TECHNIQUE: T1027.007."
) -> list[list[Any]]:
    model = _Scripted(seen=[], texts=texts, answer=answer)
    agent = _Analyst(llm=model, name="static")
    agent.run_state_block = "sample: c"
    agent.tools = [_lookup_tool()]
    with patch("maljan.agents.base_agent.loop_limits", return_value=(None, 40)):
        agent.execute_tool_loop([("system", "You are a static analyst."), ("human", task)])
    return model.seen


def _wire(messages: list[Any]) -> list[str]:
    return [json.dumps(entry, sort_keys=True) for entry in convert_to_openai_messages(messages)]


def _without_the_block_on_the_last(wire: list[str]) -> list[str]:
    out = [json.loads(entry) for entry in wire]
    content = out[-1].get("content")
    if isinstance(content, str):
        out[-1]["content"] = without_run_state_tail(content)
    elif isinstance(content, list) and content and is_run_state_block(content[-1].get("text")):
        out[-1]["content"] = content[:-1]
    return [json.dumps(entry, sort_keys=True) for entry in out]


def _assert_each_request_extends_the_last(requests: list[list[str]]) -> None:
    assert len(requests) >= 2
    for earlier, later in zip(requests, requests[1:], strict=False):
        head = _without_the_block_on_the_last(earlier)
        assert later[: len(head)] == head
        assert len(later) > len(head)


class TestTheCachedPrefixHolds:
    def test_each_loop_request_is_the_last_one_plus_new_turns(self) -> None:
        requests = _loop()
        assert len(requests) == 4
        _assert_each_request_extends_the_last([_wire(r) for r in requests])

    def test_each_id_is_stated_once_where_it_was_first_named(self) -> None:
        last = _loop()[-1]
        assert _stated(last) == ["T1027.007", "T1105", "T1071.001", "T1622"]
        # The task's id on the task, the model's ids on the answer after its turn.
        assert _stated(last[:2]) == ["T1027.007"]
        assert "T1622" in str(last[-1].content).split(TECHNIQUE_FACTS_TURN_LEAD)[-1]

    def test_a_continued_question_keeps_the_loop_s_last_request_as_its_front(self) -> None:
        """T-489: a question asked over the loop's conversation reads the loop's cached prefix."""
        last = _loop()[-1]
        kept = [*last, AIMessage(content="CLAIM: it uses T1140\nTECHNIQUE: T1140")]
        question = HumanMessage(content="Claim 1 carries T1140; is it right?")
        continued = frame_messages(without_run_state_all(kept) + [question], run_state=RUN_STATE)
        _assert_each_request_extends_the_last([_wire(last), _wire(continued)])
        # The question shows the facts of the answer's new id.
        assert _stated(continued)[-1:] == ["T1140"]

    def test_a_deepseek_request_extends_the_last(self) -> None:
        from tests.unit.llm.provider_bodies import _bound, _openai

        model = _openai("https://api.deepseek.com", "deepseek", reasoning_effort="max")
        bodies = [_bound(model, r)["messages"] for r in _loop()]
        sent = [[json.dumps(m, sort_keys=True) for m in body] for body in bodies]
        _assert_each_request_extends_the_last(sent)
        assert TECHNIQUE_FACTS_TURN_LEAD in json.dumps(bodies[-1])


def without_run_state_all(messages: list[Any]) -> list[Any]:
    from maljan.agents.base_agent import without_run_state

    return without_run_state(messages)


class TestTheAnthropicPath:
    @pytest.fixture
    def wire(self, monkeypatch: pytest.MonkeyPatch) -> Any:
        from tests.unit.llm.anthropic_wire import Wire, install, message

        usage = {"input_tokens": 10, "output_tokens": 5}

        def answer(body: dict[str, Any]) -> dict[str, Any]:
            done = sum(
                1
                for m in body["messages"]
                if m["role"] == "user" and isinstance(m["content"], list)
                for b in m["content"]
                if b.get("type") == "tool_result"
            )
            thinking = {"type": "thinking", "thinking": "", "signature": f"sig-{done}-" + "A" * 40}
            if body.get("tools") and (body.get("tool_choice") or {}).get("type") != "none":
                if done < 2:
                    said = {"type": "text", "text": f"Maybe T1105, or T162{done}."}
                    call = {
                        "type": "tool_use",
                        "id": f"toolu_{done}",
                        "name": "lookup",
                        "input": {},
                    }
                    return message([thinking, said, call], stop="tool_use", usage=usage)
                return message(
                    [thinking, {"type": "text", "text": "prose naming T1140"}],
                    stop="end_turn",
                    usage=usage,
                )
            return message(
                [thinking, {"type": "text", "text": REPORT}], stop="end_turn", usage=usage
            )

        found = Wire(answer)
        install(monkeypatch, found)
        return found

    def test_the_loop_and_its_nudge_keep_every_thinking_block_valid(
        self, wire: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import base_agent
        from maljan.core.config import Settings
        from maljan.llm.anthropic_provider import AnthropicProvider
        from tests.unit.llm.anthropic_wire import MODEL

        monkeypatch.setattr(base_agent, "loop_limits", lambda *_a, **_k: (None, 20))
        settings = Settings(
            _env_file=None,
            llm={"provider": "anthropic", "anthropic": {"api_key": "test-anthropic-key"}},
        )
        model = AnthropicProvider(settings).build_model(MODEL, 0.1, max_tokens=4096)
        agent = _Analyst(llm=model, name="static")
        agent.run_state_block = "sample: c"
        agent.tools = [_lookup_tool()]
        said = agent.execute_tool_loop(
            [("system", "You are a static analyst."), ("human", "Revise T1027.007.")]
        )
        assert wire.refused == []
        # The loop's three requests and the nudge, none asking to drop a block.
        assert len(wire.bodies) == 4
        assert not any("drop_block" in json.dumps(b) for b in wire.bodies)
        nudge = wire.bodies[-1]
        assert nudge["tool_choice"] == {"type": "none"}
        seen = json.dumps(nudge["messages"])
        for tid in ("T1027.007", "T1105", "T1620", "T1621", "T1140"):
            assert seen.count(f"- {tid} ") == 1, tid
        assert "CLAIM: it fetches a file" in said


class TestAClearedAnswerKeepsItsFacts:
    def test_the_note_is_put_back_after_the_reference(self) -> None:
        messages = _facts(
            [
                HumanMessage(content="go"),
                _call(0, "T1105"),
                ToolMessage("[ev_0001]\nx", tool_call_id="c0"),
                _call(1),
            ]
        )
        cleared = messages[2].model_copy(update={"content": "[cleared ev_0001: 9 chars]"})
        out = notes_kept_after_clearing([*messages[:2], cleared, messages[3]])
        assert out[2].content == f"[cleared ev_0001: 9 chars]\n\n{_note('T1105')}"
        assert out[0] is messages[0] and out[3] is messages[3]
        # Kept where it stands, before a run-state block that follows it.
        framed = frame_messages(messages[:3], run_state=RUN_STATE)
        assert notes_kept_after_clearing(framed)[2] is framed[2]
