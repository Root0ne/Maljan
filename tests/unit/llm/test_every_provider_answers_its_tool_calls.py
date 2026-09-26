"""Every provider's request answers each tool call it carries.

Each API pairs a call with its reply and refuses a history where one is
missing: OpenAI-compatible servers want a ``tool`` message per call id,
Anthropic a ``tool_result`` per ``tool_use`` at the front of the next user
turn, Gemini as many ``functionResponse`` parts as the model turn has
``functionCall`` parts, and Ollama takes the OpenAI shape. A call no tool ran
— never answered, or with arguments that did not parse — is sent with a reply
that says only what is known; the call stays as the model wrote it. A history
that is already well formed is sent as it was.

Through the request each client actually builds; no request leaves the
process.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from pydantic import SecretStr

from maljan.core.config import Settings
from maljan.llm.tool_replies import (
    NO_REPLY_RECORDED,
    NOT_RUN_REPLY,
    answered_anthropic_messages,
    answered_messages,
    with_answered_tool_calls,
)


def _settings() -> Settings:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    settings.llm.openai.api_key = SecretStr("key")
    settings.llm.openai.base_url = "https://api.example.com"
    settings.llm.openai.compat = "standard"  # type: ignore[assignment]
    settings.llm.anthropic.api_key = SecretStr("key")
    settings.llm.gemini.api_key = SecretStr("key")
    return settings


def _openai(model: str = "m", **kwargs: Any) -> Any:
    from maljan.llm.openai_provider import OpenAIProvider, forget_standard_only

    forget_standard_only()
    return OpenAIProvider(_settings()).build_model(model, 0.0, max_tokens=64, **kwargs)


def _codex() -> Any:
    # A model name the OpenAI client sends through the Responses API.
    return _openai("gpt-5-codex")


def _reasoning() -> Any:
    # ``reasoning`` set sends any model through the Responses API.
    return _openai("m", reasoning={"effort": "low"})


def _anthropic() -> Any:
    from maljan.llm.anthropic_provider import AnthropicProvider

    return AnthropicProvider(_settings()).build_model("m", 0.0, max_tokens=64)


def _gemini() -> Any:
    from maljan.llm.gemini_provider import GeminiProvider

    return GeminiProvider(_settings()).build_model("gemini-example", 0.0)


def _ollama() -> Any:
    from maljan.llm.ollama_provider import OllamaProvider

    return OllamaProvider(_settings()).build_model("m", 0.0)


def _openai_history(model: Any, messages: list[Any], *, base: bool = False) -> list[Any]:
    owner = type(model).__mro__[1] if base else type(model)
    return owner._get_request_payload(model, messages)["messages"]  # type: ignore[no-any-return]


def _responses_history(model: Any, messages: list[Any], *, base: bool = False) -> list[Any]:
    owner = type(model).__mro__[1] if base else type(model)
    payload = owner._get_request_payload(model, messages)
    assert "messages" not in payload
    return payload["input"]  # type: ignore[no-any-return]


def _anthropic_history(model: Any, messages: list[Any], *, base: bool = False) -> list[Any]:
    return _openai_history(model, messages, base=base)


def _gemini_history(model: Any, messages: list[Any], *, base: bool = False) -> list[Any]:
    owner = type(model).__mro__[1] if base else type(model)
    return owner._prepare_request(model, messages)["contents"]  # type: ignore[no-any-return]


def _ollama_history(model: Any, messages: list[Any], *, base: bool = False) -> list[Any]:
    owner = type(model).__mro__[1] if base else type(model)
    return owner._chat_params(model, messages)["messages"]  # type: ignore[no-any-return]


def _openai_unanswered(sent: list[dict[str, Any]]) -> list[str]:
    """Each call id no tool message right after its turn answers, as the server checks."""
    missing: list[str] = []
    for index, message in enumerate(sent):
        if message.get("role") != "assistant" or not message.get("tool_calls"):
            continue
        answered: set[str] = set()
        for later in sent[index + 1 :]:
            if later.get("role") != "tool":
                break
            answered.add(str(later.get("tool_call_id")))
        missing += [str(c["id"]) for c in message["tool_calls"] if str(c["id"]) not in answered]
    # And a tool message that answers no call of the turn it follows, which the
    # server refuses too.
    owner: set[str] = set()
    for message in sent:
        if message.get("role") == "assistant" and message.get("tool_calls"):
            owner = {str(c["id"]) for c in message["tool_calls"]}
        elif message.get("role") == "tool":
            if str(message.get("tool_call_id")) not in owner:
                missing.append(f"orphan {message.get('tool_call_id')}")
        else:
            owner = set()
    return missing


def _responses_unanswered(sent: list[dict[str, Any]]) -> list[str]:
    """Each ``function_call`` with no output, and each output with no call."""
    calls = [str(i["call_id"]) for i in sent if i.get("type") == "function_call"]
    outputs = [str(i["call_id"]) for i in sent if i.get("type") == "function_call_output"]
    return [c for c in calls if c not in outputs] + [
        f"orphan {o}" for o in outputs if o not in calls
    ]


def _responses_replies(sent: list[dict[str, Any]]) -> dict[str, str]:
    return {str(i["call_id"]): i["output"] for i in sent if i.get("type") == "function_call_output"}


def _openai_replies(sent: list[dict[str, Any]]) -> dict[str, str]:
    return {str(m["tool_call_id"]): m["content"] for m in sent if m.get("role") == "tool"}


def _anthropic_unanswered(sent: list[dict[str, Any]]) -> list[str]:
    """Each ``tool_use`` id the front of the next user turn does not answer."""
    missing: list[str] = []
    for index, message in enumerate(sent):
        content = message.get("content")
        if message.get("role") != "assistant" or not isinstance(content, list):
            continue
        ids = [b["id"] for b in content if isinstance(b, dict) and b.get("type") == "tool_use"]
        if not ids:
            continue
        following = sent[index + 1] if index + 1 < len(sent) else {}
        answered: set[str] = set()
        blocks = following.get("content") if following.get("role") == "user" else []
        for block in blocks if isinstance(blocks, list) else []:
            if not (isinstance(block, dict) and block.get("type") == "tool_result"):
                break
            answered.add(block["tool_use_id"])
        missing += [i for i in ids if i not in answered]
    # And a result that answers no call of the assistant turn before it.
    owner: set[str] = set()
    for message in sent:
        content = message.get("content")
        blocks = content if isinstance(content, list) else []
        if message.get("role") == "assistant":
            owner = {b["id"] for b in blocks if isinstance(b, dict) and b.get("type") == "tool_use"}
            continue
        missing += [
            f"orphan {b['tool_use_id']}"
            for b in blocks
            if isinstance(b, dict)
            and b.get("type") == "tool_result"
            and b["tool_use_id"] not in owner
        ]
        owner = set()
    return missing


def _anthropic_replies(sent: list[dict[str, Any]]) -> dict[str, str]:
    return {
        b["tool_use_id"]: b["content"]
        for m in sent
        if m.get("role") == "user" and isinstance(m.get("content"), list)
        for b in m["content"]
        if isinstance(b, dict) and b.get("type") == "tool_result"
    }


def _gemini_unanswered(sent: list[Any]) -> list[str]:
    """Each ``functionCall`` name the next user turn's responses leave unanswered, in order."""
    missing: list[str] = []
    for index, content in enumerate(sent):
        calls = [p.function_call.name for p in content.parts or [] if p.function_call]
        if content.role != "model" or not calls:
            continue
        following = sent[index + 1] if index + 1 < len(sent) else None
        names = (
            [p.function_response.name for p in following.parts or [] if p.function_response]
            if following is not None and following.role == "user"
            else []
        )
        missing += calls[len(names) :]
        missing += [c for c, n in zip(calls, names, strict=False) if c != n]
    return missing


def _gemini_replies(sent: list[Any]) -> list[tuple[str, Any]]:
    return [
        (p.function_response.name, p.function_response.response.get("output"))
        for content in sent
        for p in content.parts or []
        if p.function_response
    ]


PROVIDERS = [
    pytest.param(_openai, _openai_history, _openai_unanswered, id="openai"),
    pytest.param(_codex, _responses_history, _responses_unanswered, id="openai-responses-codex"),
    pytest.param(
        _reasoning, _responses_history, _responses_unanswered, id="openai-responses-reasoning"
    ),
    pytest.param(_anthropic, _anthropic_history, _anthropic_unanswered, id="anthropic"),
    pytest.param(_gemini, _gemini_history, _gemini_unanswered, id="gemini"),
    pytest.param(_ollama, _ollama_history, _openai_unanswered, id="ollama"),
]


def _call(call_id: str, name: str, what: str) -> dict[str, Any]:
    return {"name": name, "args": {"what": what}, "id": call_id, "type": "tool_call"}


def _dangling() -> list[Any]:
    """A turn with two parsed calls, one of them answered, then the next instruction."""
    return [
        SystemMessage(content="sys"),
        HumanMessage(content="task"),
        AIMessage(content="", tool_calls=[_call("one", "lookup", "a"), _call("two", "fetch", "b")]),
        ToolMessage(content="a's answer", tool_call_id="one"),
        HumanMessage(content="Write your report now."),
    ]


def _with_unparsed() -> list[Any]:
    """A turn with a parsed call that has no reply and a call whose arguments were cut."""
    return [
        SystemMessage(content="sys"),
        HumanMessage(content="task"),
        AIMessage(
            content="",
            tool_calls=[_call("one", "lookup", "a")],
            invalid_tool_calls=[
                {
                    "name": "lookup",
                    "args": '{"what": "b',
                    "id": "cut",
                    "error": None,
                    "type": "invalid_tool_call",
                }
            ],
        ),
        HumanMessage(content="Write your report now."),
    ]


def _away() -> list[Any]:
    """A turn whose second call's reply was recorded, but not right after the turn."""
    return [
        SystemMessage(content="sys"),
        HumanMessage(content="task"),
        AIMessage(content="", tool_calls=[_call("one", "lookup", "a"), _call("two", "fetch", "b")]),
        ToolMessage(content="a's answer", tool_call_id="one"),
        HumanMessage(content="Go on."),
        AIMessage(content="noted"),
        ToolMessage(content="b's answer", tool_call_id="two"),
        HumanMessage(content="Write your report now."),
    ]


def _answered() -> list[Any]:
    return [
        SystemMessage(content="sys"),
        HumanMessage(content="task"),
        AIMessage(content="", tool_calls=[_call("one", "lookup", "a"), _call("two", "fetch", "b")]),
        ToolMessage(content="a's answer", tool_call_id="one"),
        ToolMessage(content="b's answer", tool_call_id="two"),
        HumanMessage(content="Write your report now."),
    ]


@pytest.mark.parametrize(("build", "history", "unanswered"), PROVIDERS)
def test_an_unanswered_call_is_sent_with_a_reply_saying_so(
    build: Any, history: Any, unanswered: Any
) -> None:
    model = build()

    sent = history(model, _dangling())

    assert unanswered(sent) == []
    # The client alone would have sent the call unanswered.
    assert unanswered(history(model, _dangling(), base=True)) != []


@pytest.mark.parametrize(("build", "history", "unanswered"), PROVIDERS)
def test_a_turn_with_an_unparsed_call_sends_a_well_formed_request(
    build: Any, history: Any, unanswered: Any
) -> None:
    model = build()

    sent = history(model, _with_unparsed())

    assert unanswered(sent) == []
    # The client alone would have sent the call unanswered.
    assert unanswered(history(model, _with_unparsed(), base=True)) != []


@pytest.mark.parametrize(("build", "history", "unanswered"), PROVIDERS)
def test_a_fully_answered_history_is_sent_unchanged(
    build: Any, history: Any, unanswered: Any
) -> None:
    model = build()

    sent = history(model, _answered())

    assert unanswered(sent) == []
    assert sent == history(model, _answered(), base=True)


def test_the_replies_on_the_openai_serializer() -> None:
    replies = _openai_replies(_openai_history(_openai(), _with_unparsed()))

    # The client writes the cut call into the turn, so the reply says it was not run.
    assert replies == {"one": NO_REPLY_RECORDED, "cut": NOT_RUN_REPLY}


def test_the_replies_on_the_ollama_serializer() -> None:
    sent = _ollama_history(_ollama(), _dangling())

    assert [m["role"] for m in sent] == ["system", "user", "assistant", "tool", "tool", "user"]
    assert sent[4] == {
        "role": "tool",
        "content": NO_REPLY_RECORDED,
        "images": [],
        "tool_call_id": "two",
    }
    # A cut call is not written into Ollama's request, so nothing answers it.
    assert _openai_replies(_ollama_history(_ollama(), _with_unparsed())) == {
        "one": NO_REPLY_RECORDED
    }


def test_the_replies_on_the_anthropic_serializer() -> None:
    sent = _anthropic_history(_anthropic(), _dangling())

    assert [m["role"] for m in sent] == ["user", "assistant", "user"]
    # The replies at the front of the user turn, in call order, its text after them.
    assert [b.get("tool_use_id", b.get("text")) for b in sent[2]["content"]] == [
        "one",
        "two",
        "Write your report now.",
    ]
    assert _anthropic_replies(sent) == {"one": "a's answer", "two": NO_REPLY_RECORDED}


def test_an_anthropic_tool_use_block_whose_input_was_cut_is_said_not_run() -> None:
    turn = AIMessage(
        content=[{"type": "tool_use", "id": "toolu_cut", "name": "lookup", "input": {}}],
        invalid_tool_calls=[
            {
                "name": "lookup",
                "args": '{"what": "b',
                "id": "toolu_cut",
                "error": None,
                "type": "invalid_tool_call",
            }
        ],
    )
    sent = _anthropic_history(_anthropic(), [HumanMessage(content="task"), turn])

    # The turn stays as the model wrote it; a user turn holding the reply follows.
    assert sent[1]["content"] == [
        {"type": "tool_use", "id": "toolu_cut", "name": "lookup", "input": {}}
    ]
    assert sent[2] == {
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": "toolu_cut", "content": NOT_RUN_REPLY}],
    }


def test_the_replies_on_the_gemini_serializer() -> None:
    sent = _gemini_history(_gemini(), _dangling())

    assert [c.role for c in sent] == ["user", "model", "user", "user"]
    assert _gemini_replies(sent) == [("lookup", "a's answer"), ("fetch", NO_REPLY_RECORDED)]


def test_gemini_replies_follow_the_call_order_the_parts_are_paired_by() -> None:
    # Only the second call was answered; Gemini pairs by name and order, so the
    # known-only reply has to sit in the first call's place.
    history = _dangling()
    history[3] = ToolMessage(content="b's answer", tool_call_id="two")

    sent = _gemini_history(_gemini(), history)

    assert _gemini_replies(sent) == [("lookup", NO_REPLY_RECORDED), ("fetch", "b's answer")]


def test_the_model_turn_is_not_changed_on_any_serializer() -> None:
    for build, history in (
        (_openai, _openai_history),
        (_anthropic, _anthropic_history),
        (_ollama, _ollama_history),
    ):
        model = build()
        sent = history(model, _dangling())
        base = history(model, _dangling(), base=True)
        turn = next(m for m in base if m["role"] == "assistant")
        assert turn in sent
    gemini = _gemini()
    base_turn = next(
        c for c in _gemini_history(gemini, _dangling(), base=True) if c.role == "model"
    )
    assert base_turn in _gemini_history(gemini, _dangling())


class TestTheCompletersOnTheirOwn:
    def test_an_anthropic_turn_at_the_end_gets_a_user_turn_of_replies(self) -> None:
        messages = [
            {"role": "user", "content": "t"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "a", "name": "f"}]},
        ]

        out, written = answered_anthropic_messages(messages)

        assert written == 1
        assert out[:2] == messages
        assert out[2] == {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": "a", "content": NO_REPLY_RECORDED}],
        }

    def test_an_anthropic_history_already_answered_comes_back_as_it_was(self) -> None:
        messages = [
            {"role": "assistant", "content": [{"type": "tool_use", "id": "a", "name": "f"}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a"}]},
        ]

        assert answered_anthropic_messages(messages) == (messages, 0)

    def test_a_conversation_already_answered_comes_back_as_it_was(self) -> None:
        messages = _answered()

        assert answered_messages(messages) == (messages, 0)

    def test_a_reply_that_answers_no_call_stays_after_the_turns_replies(self) -> None:
        messages = [
            AIMessage(content="", tool_calls=[_call("a", "f", "x")]),
            ToolMessage(content="stray", tool_call_id="z"),
        ]

        out, written = answered_messages(messages)

        assert written == 1
        assert [m.tool_call_id for m in out[1:]] == ["a", "z"]
        assert out[1].content == NO_REPLY_RECORDED

    def test_a_class_without_the_hook_is_returned_as_it_is(self) -> None:
        class _Plain:
            pass

        assert with_answered_tool_calls(_Plain, "ollama") is _Plain


@pytest.mark.parametrize(("build", "history", "unanswered"), PROVIDERS)
def test_a_reply_recorded_away_from_its_turn_is_sent_not_said_missing(
    build: Any, history: Any, unanswered: Any
) -> None:
    sent = history(build(), _away())

    assert unanswered(sent) == []
    # Both replies were recorded; neither is said missing.
    assert NO_REPLY_RECORDED not in repr(sent)
    assert "b's answer" in repr(sent)


def test_a_gemini_reply_recorded_away_from_its_turn_is_sent_as_the_client_builds_it() -> None:
    model = _gemini()

    sent = _gemini_history(model, _away())

    # The client finds a reply anywhere in the conversation by its id, so the
    # request it builds alone is already right and is sent unchanged.
    assert sent == _gemini_history(model, _away(), base=True)
    assert _gemini_replies(sent) == [("lookup", "a's answer"), ("fetch", "b's answer")]


def test_a_chat_reply_recorded_away_from_its_turn_is_moved_to_its_call() -> None:
    sent = _openai_history(_openai(), _away())

    assert [m["role"] for m in sent] == [
        "system",
        "user",
        "assistant",
        "tool",
        "tool",
        "user",
        "assistant",
        "user",
    ]
    assert _openai_replies(sent) == {"one": "a's answer", "two": "b's answer"}


def test_an_anthropic_result_recorded_away_from_its_turn_is_moved_to_its_call() -> None:
    sent = _anthropic_history(_anthropic(), _away())

    assert [m["role"] for m in sent] == ["user", "assistant", "user", "assistant", "user"]
    assert [b.get("tool_use_id", b.get("text")) for b in sent[2]["content"]] == [
        "one",
        "two",
        "Go on.",
    ]
    # The user turn it came from keeps what else it says.
    assert sent[4]["content"] == [{"type": "text", "text": "Write your report now."}]


def test_gemini_pairs_two_calls_of_one_name_by_position() -> None:
    history = [
        HumanMessage(content="task"),
        AIMessage(
            content="", tool_calls=[_call("one", "lookup", "a"), _call("two", "lookup", "b")]
        ),
        ToolMessage(content="b's answer", tool_call_id="two"),
        HumanMessage(content="Write your report now."),
    ]

    sent = _gemini_history(_gemini(), history)

    assert _gemini_replies(sent) == [("lookup", NO_REPLY_RECORDED), ("lookup", "b's answer")]


def test_the_replies_on_the_responses_api_serializer() -> None:
    sent = _responses_history(_codex(), _with_unparsed())

    # The client writes the cut call as a function_call, so its output says not run.
    assert _responses_replies(sent) == {"one": NO_REPLY_RECORDED, "cut": NOT_RUN_REPLY}
    kinds = [i.get("type") for i in sent]
    assert kinds.index("function_call_output") > kinds.index("function_call")
    assert sent[-1]["role"] == "user"


def test_the_completion_counts_what_it_wrote() -> None:
    from maljan.llm.tool_replies import MOVED, NOT_RUN, WRITTEN, answered_tool_calls

    record: list[str] = []
    messages = [
        {"role": "assistant", "content": None, "tool_calls": [{"id": "a"}, {"id": "b"}]},
        {"role": "user", "content": NOT_RUN_REPLY},
        {"role": "assistant", "content": "x"},
        {"role": "tool", "tool_call_id": "c", "content": "late"},
        {"role": "assistant", "content": None, "tool_calls": [{"id": "d"}]},
    ]
    messages.insert(1, {"role": "tool", "tool_call_id": "zz", "content": "stray"})
    messages[0]["tool_calls"].append({"id": "c"})

    answered_tool_calls(messages, frozenset({"b"}), record=record)

    # A user message that happens to hold the not-run sentence is not counted.
    assert record == [WRITTEN, NOT_RUN, MOVED, WRITTEN]
