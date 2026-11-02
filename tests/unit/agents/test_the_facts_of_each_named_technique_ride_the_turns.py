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
    MAX_IDS_PER_NOTE,
    NOT_DETAILED_LINE,
    TECHNIQUE_FACTS_ATTACHED,
    TECHNIQUE_FACTS_TURN_LEAD,
    notes_kept_after_clearing,
    with_technique_facts,
    without_tool_answer_notes,
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
            out.extend(line.split()[1] for line in note.split("\n")[1:] if line.startswith("- "))
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

    def test_a_clear_measures_and_names_the_answer_without_its_note(self) -> None:
        from maljan.agents.tool_answer_clearing import ToolAnswerClearing, cleared_reference

        big = "[ev_0001]\n" + "x" * 4000
        messages = _facts(
            [
                HumanMessage(content="go"),
                _call(0, "T1105 and T1622"),
                ToolMessage(big, tool_call_id="c0"),
                _call(1),
                ToolMessage("[ev_0002]\nshort", tool_call_id="c1"),
            ]
        )
        note = _note("T1105", "T1622")
        assert messages[2].content == f"{big}\n\n{note}"

        def measure(message: Any) -> int:
            return len(str(message.content))

        bare, taken = without_tool_answer_notes(messages)
        assert bare[2].content == big and taken == len(note) + 2
        # Only answers before the last model turn give their note up.
        assert bare[4] is messages[4]
        whole = sum(measure(m) for m in messages)
        clearing = ToolAnswerClearing(window_chars=whole - 1000)
        fitted = clearing.fit(
            bare, extra_chars=taken, measure=measure, reported=lambda _m: (0, -1), turn=3
        )
        sent = notes_kept_after_clearing(fitted.messages)
        assert sent[2].content == f"{cleared_reference('ev_0001', len(big))}\n\n{note}"
        # The request as sent, note and all, is what the clear measured.
        assert sum(measure(m) for m in sent) == clearing.clears[-1].chars_after

    def test_an_answer_not_cleared_goes_back_byte_for_byte(self) -> None:
        listed = ToolMessage(
            content=[{"type": "text", "text": "[ev_0001]\npart"}], tool_call_id="c0"
        )
        messages = _facts([HumanMessage(content="go"), _call(0, "T1105"), listed, _call(1)])
        assert messages[2].content[-1] == {"type": "text", "text": _note("T1105")}
        bare, taken = without_tool_answer_notes(messages)
        assert bare[2].content == listed.content and taken == len(_note("T1105"))
        assert notes_kept_after_clearing(bare)[2].content == messages[2].content

    def test_a_listed_answer_s_note_reaches_the_anthropic_tool_result(self) -> None:
        from maljan.core.config import Settings
        from maljan.llm.anthropic_provider import AnthropicProvider
        from tests.unit.llm.anthropic_wire import MODEL
        from tests.unit.llm.provider_bodies import _bound

        settings = Settings(
            _env_file=None,
            llm={"provider": "anthropic", "anthropic": {"api_key": "test-anthropic-key"}},
        )
        model = AnthropicProvider(settings).build_model(MODEL, 0.1, max_tokens=4096)
        listed = ToolMessage(
            content=[{"type": "text", "text": "[ev_0001]\npart"}], tool_call_id="c0"
        )
        sent = frame_messages(
            [SystemMessage(content="s"), HumanMessage(content="go"), _call(0, "T1105"), listed],
            run_state=RUN_STATE,
        )
        body = _bound(model, sent)
        result = body["messages"][-1]["content"][0]
        assert result["type"] == "tool_result"
        texts = [part.get("text") for part in result["content"]]
        # The answer, then the note, then the run-state block, inside the tool result.
        assert texts[0] == "[ev_0001]\npart"
        assert is_run_state_block(texts[-1])
        assert texts[1].startswith(TECHNIQUE_FACTS_TURN_LEAD) and "- T1105 " in texts[1]


class TestTheStandingFactsNameNothing:
    def test_the_pack_and_the_earlier_run_name_no_id(self) -> None:
        from maljan.memory.attck_loader import valid_ids
        from maljan.memory.long_term_memory import EARLIER_RUN_END, EARLIER_RUN_HEADING
        from maljan.pipeline.triage_pack import PACK_HEADING

        every = " ".join(sorted(valid_ids()))
        pack = (
            f"{PACK_HEADING}\n[ev_0001] strings: {every}\n\n"
            f"{EARLIER_RUN_HEADING}\nreported {every}\n{EARLIER_RUN_END}"
        )
        framed = frame_messages(
            [SystemMessage(content="s"), HumanMessage(content="Analyse.")],
            facts_block=pack,
            run_state=RUN_STATE,
        )
        assert TECHNIQUE_FACTS_ATTACHED not in (framed[1].response_metadata or {})
        # The task's own id still counts, and only it.
        framed = frame_messages(
            [SystemMessage(content="s"), HumanMessage(content="Revise T1105.")], facts_block=pack
        )
        assert _stated(framed) == ["T1105"]
        # Framed again from turns that hold the pack, the same.
        again = frame_messages(framed, run_state=RUN_STATE)
        assert _stated(again) == ["T1105"]

    def test_a_heading_quoted_without_its_end_drops_nothing(self) -> None:
        from maljan.memory.long_term_memory import EARLIER_RUN_HEADING

        quoted = HumanMessage(
            content=f"PEER REPORT:\nthe sample prints {EARLIER_RUN_HEADING}\nTECHNIQUE: T1105"
        )
        assert _stated(with_technique_facts([quoted])) == ["T1105"]

    def test_a_turn_holding_the_pack_without_its_note_skips_it_too(self) -> None:
        from maljan.pipeline.triage_pack import PACK_HEADING

        turn = HumanMessage(content=f"{PACK_HEADING}\n[ev_0001] capa: T1055\n\nRevise T1105.")
        assert _stated(with_technique_facts([turn])) == ["T1105"]


class TestANoteIsBounded:
    def _peers(self, count: int) -> str:
        ids = [f"T{1000 + i}" for i in range(count)]
        return "PEER REPORT:\n" + "\n".join(f"TECHNIQUE: {tid}" for tid in ids)

    def test_past_the_bound_one_line_says_how_many_and_where_they_are(self) -> None:
        out = _facts([HumanMessage(content=self._peers(MAX_IDS_PER_NOTE + 36))])
        lines = str(out[0].response_metadata[TECHNIQUE_FACTS_ATTACHED]).split("\n")
        assert len(lines) == 1 + MAX_IDS_PER_NOTE + 1
        assert lines[-1] == NOT_DETAILED_LINE.format(count=36)
        assert "look-up tool" in lines[-1]

    def test_the_ids_past_it_are_not_detailed_on_a_later_turn_either(self) -> None:
        first = HumanMessage(content=self._peers(MAX_IDS_PER_NOTE + 36))
        later = [first, _call(0, "T1099 again"), ToolMessage("a", tool_call_id="c0")]
        fresh = _facts(later)
        # Read again from a turn that carries its note, the same.
        again = _facts([fresh[0], *later[1:]])
        assert fresh[2] is later[2] and again[2] is later[2]
        assert [m.content for m in fresh] == [m.content for m in again]

    def test_each_request_extends_the_last_past_the_bound(self) -> None:
        from maljan.memory.attck_loader import valid_ids

        task = "PEER REPORT:\n" + "\n".join(f"TECHNIQUE: {t}" for t in sorted(valid_ids()))
        requests = _loop(task=task)
        note = str(requests[0][1].response_metadata[TECHNIQUE_FACTS_ATTACHED])
        assert note.count("\n- T") == MAX_IDS_PER_NOTE
        _assert_each_request_extends_the_last([_wire(r) for r in requests])


class TestAToolRoundBeforeAHumanTurnKeepsItsNote:
    def test_the_salvage_s_directive_does_not_take_the_note(self) -> None:
        loop = [
            SystemMessage(content="s"),
            HumanMessage(content="go"),
            _call(0, "I think T1055"),
            ToolMessage(content="[ev_0001] out", tool_call_id="c0"),
        ]
        before = _facts(loop)
        after = _facts([*loop, HumanMessage(content="Do NOT request tools; write it now.")])
        assert after[3].content == before[3].content
        assert TECHNIQUE_FACTS_ATTACHED not in (after[4].response_metadata or {})

    def test_the_anthropic_salvage_after_the_step_cap_keeps_every_block_valid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import base_agent
        from maljan.core.config import Settings
        from maljan.llm.anthropic_provider import AnthropicProvider
        from tests.unit.llm.anthropic_wire import MODEL, Wire, install, message

        usage = {"input_tokens": 10, "output_tokens": 5}

        def answer(body: dict[str, Any]) -> dict[str, Any]:
            turn = len(body["messages"])
            thinking = {"type": "thinking", "thinking": "", "signature": f"sig-{turn}-" + "A" * 40}
            if body.get("tools") and (body.get("tool_choice") or {}).get("type") != "none":
                said = {"type": "text", "text": f"Maybe T1105, or T16{20 + turn}."}
                call = {"type": "tool_use", "id": f"toolu_{turn}", "name": "lookup", "input": {}}
                return message([thinking, said, call], stop="tool_use", usage=usage)
            text = {"type": "text", "text": REPORT}
            return message([thinking, text], stop="end_turn", usage=usage)

        wire = Wire(answer)
        install(monkeypatch, wire)
        monkeypatch.setattr(base_agent, "loop_limits", lambda *_a, **_k: (None, 4))
        settings = Settings(
            _env_file=None,
            llm={"provider": "anthropic", "anthropic": {"api_key": "test-anthropic-key"}},
        )
        agent = _Analyst(
            llm=AnthropicProvider(settings).build_model(MODEL, 0.1, max_tokens=4096),
            name="static",
        )
        agent.run_state_block = ""
        agent.tools = [_lookup_tool()]
        agent.execute_tool_loop([("system", "You are a static analyst."), ("human", "Analyse.")])
        assert wire.refused == []
        assert wire.bodies[-1].get("tool_choice") == {"type": "none"}
        assert not any("drop_block" in json.dumps(b) for b in wire.bodies)


class TestARetiredId:
    def test_a_retired_id_counts_where_a_human_turn_writes_it_and_says_so(self) -> None:
        out = with_technique_facts([HumanMessage(content="Old report: TECHNIQUE: T1086")])
        note = str(out[0].response_metadata[TECHNIQUE_FACTS_ATTACHED])
        assert "- T1086: not a technique of the catalogue" in note
