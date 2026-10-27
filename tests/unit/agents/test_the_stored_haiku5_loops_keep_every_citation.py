"""The stored haiku5 tool loops, replayed through the tier clear: every citation stays resolvable.

``tests/fixtures/clearing/haiku5_tool_loops.json`` is every tool loop of the
stored Claude Haiku 5.5 run (job ``a58dae16``): per request the usage the
server reported, the ledger ids the model turn's own text wrote (its streamed
text), and the stamped answers that turn's calls brought back, with their
characters and their estimated tokens (the request-to-request growth the
server reported, less the turn's own replayed output, spread over the turn's
answers by their characters); per loop the ids its answer cites (its last
turn and the claims the agent published next).

Each loop is rebuilt as the conversation its requests sent, in tokens, and
sent through :class:`ToolAnswerClearing` with the boundary of the vendored
Claude Haiku 5.5 price row and the agent's own cost check. Every id a loop's
answer cites is still in the conversation whole or behind a reference
``read_evidence`` answers; no answer is cleared before the model cited it.
Where what no tier clear can take is already past the boundary (the
reverser's first request is 131,680 tokens) nothing is cleared at all, and
the loop sends what it sent. With a boundary each loop can get back under by
clearing cited answers, and no cost check, the loops clear (the reverser's
long loops among them) and the same holds.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from maljan.agents import tool_answer_clearing as tac
from maljan.core.spend import SpendMeter, prompt_tier_tokens

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "clearing" / "haiku5_tool_loops.json"
MODEL = "claude-haiku-5-5"


def _loops() -> list[dict[str, Any]]:
    return [loop for loop in json.loads(FIXTURE.read_text())["loops"] if len(loop["turns"]) > 1]


def _sized(message: Any, tokens: int) -> Any:
    message.additional_kwargs["replay_tokens"] = int(tokens)
    return message


def replay(
    loop: dict[str, Any],
    tier: int | None,
    price: Any,
    *,
    priced: bool = True,
    hour_writes: bool = False,
) -> dict[str, Any]:
    """One stored loop sent through the clearing: what each request weighed, and what was cleared.

    Sizes are tokens (one budget character a token). A reference weighs its
    characters at the loop's own characters per answer token. ``priced``
    false leaves the cost check out, so a boundary that is no price's still
    clears.
    """
    answers = [a for turn in loop["turns"] for a in turn["answers"]]
    ratio = (sum(a[1] for a in answers) / max(1, sum(a[2] for a in answers))) if answers else 3.0
    ratio = ratio if ratio > 0 else 3.0

    def measure(message: Any) -> int:
        content = str(getattr(message, "content", ""))
        if isinstance(message, ToolMessage) and content.startswith("[cleared "):
            return max(1, int(len(content) / ratio))
        return int(message.additional_kwargs.get("replay_tokens", 0))

    def reported(messages: list[Any]) -> tuple[int, int]:
        for index in range(len(messages) - 1, -1, -1):
            usage = getattr(messages[index], "usage_metadata", None) or {}
            if isinstance(messages[index], AIMessage) and usage.get("input_tokens"):
                after = sum(measure(m) for m in messages[index:])
                return int(usage["input_tokens"]) + after, index
        return 0, -1

    def pays(before: int, cached: int, after: int, messages: list[Any]) -> bool:
        outs = [
            int((m.usage_metadata or {}).get("output_tokens") or 0)
            for m in messages
            if isinstance(m, AIMessage) and m.usage_metadata
        ]
        mean = sum(outs) // len(outs) if outs else 0
        return tac.tier_clear_pays(price, before, cached, after, mean, hour_writes=hour_writes)

    clearing = tac.ToolAnswerClearing(tier_chars=tier, tier_pays=pays if priced else None)
    turns = loop["turns"]
    conversation: list[Any] = [_sized(HumanMessage(content="framing"), turns[0]["input"])]
    sent: list[dict[str, Any]] = []
    cited_when_cleared: list[bool] = []
    call = 0
    for index, turn in enumerate(turns):
        before = set(clearing._references)
        fitted = clearing.fit(
            conversation, extra_chars=0, measure=measure, reported=reported, turn=index + 1
        )
        size = sum(measure(m) for m in fitted.messages)
        if fitted.clearing is not None:
            cited = tac.cited_ids(conversation)
            for message in fitted.messages:
                key = str(getattr(message, "tool_call_id", "") or "")
                if key and key in clearing._references and key not in before:
                    cleared_id = str(message.content)[len("[cleared ") :].split("]")[0]
                    cited_when_cleared.append(cleared_id in cited)
        sent.append(
            {"size": size, "cleared": fitted.clearing is not None, "output": turn["output"]}
        )
        calls = [
            {"name": "tool", "args": {"n": call + slot}, "id": f"c{call + slot}"}
            for slot in range(len(turn["answers"]))
        ]
        call += len(calls)
        ai = AIMessage(
            content=" ".join(turn["cites"]),
            tool_calls=calls,
            usage_metadata={
                "input_tokens": size,
                "output_tokens": turn["output"],
                "total_tokens": size + turn["output"],
            },
        )
        conversation.append(_sized(ai, turn["other_growth"]))
        for spec, (entry_id, chars, tokens) in zip(calls, turn["answers"], strict=True):
            conversation.append(
                _sized(
                    ToolMessage(content=f"[{entry_id}]\n" + "x" * chars, tool_call_id=spec["id"]),
                    tokens,
                )
            )
    final = clearing.apply(conversation)
    whole = {
        found for m in final if isinstance(m, ToolMessage) and (found := tac.stamp_of(m.content))
    }
    cleared = {
        str(m.content)[len("[cleared ") :].split("]")[0]
        for m in final
        if isinstance(m, ToolMessage) and str(m.content).startswith("[cleared ")
    }
    return {
        "sent": sent,
        "whole": whole,
        "cleared": cleared,
        "cited_when_cleared": cited_when_cleared,
        "own": {a[0] for a in answers},
    }


def cost(price: Any, sent: list[dict[str, Any]]) -> float:
    """What the requests cost: each reads the one before it from the cache unless it cleared."""
    total, previous = 0.0, 0
    for request in sent:
        cached = 0 if request["cleared"] else min(previous, request["size"])
        total += price.cost(
            {
                "input_tokens": request["size"],
                "cached_input_tokens": cached,
                "cache_write_input_tokens": request["size"] - cached,
                "output_tokens": request["output"],
            }
        )
        previous = request["size"]
    return total


def _price() -> Any:
    price = SpendMeter().price_of(MODEL)
    assert price is not None and prompt_tier_tokens(price) is not None
    return price


def _check(loop: dict[str, Any], tier: int, *, priced: bool = True) -> dict[str, Any]:
    result = replay(loop, tier, _price(), priced=priced)
    tool = tac.read_evidence_tool(lambda wanted: "stored" if wanted in result["own"] else None)
    for wanted in loop["final_cites"]:
        if wanted not in result["own"]:
            continue  # cited from the pack, a peer or an earlier round, never this loop's
        assert wanted in result["whole"] or wanted in result["cleared"], wanted
        if wanted in result["cleared"]:
            assert tool.invoke({"evidence_id": wanted}) == "stored"
    assert all(result["cited_when_cleared"])
    return result


@pytest.mark.parametrize("loop", _loops(), ids=lambda loop: loop["agent"])
def test_at_the_model_s_own_boundary_every_citation_is_whole_or_read_again(
    loop: dict[str, Any],
) -> None:
    _check(loop, int(prompt_tier_tokens(_price()) or 0))


@pytest.mark.parametrize("loop", _loops(), ids=lambda loop: loop["agent"])
@pytest.mark.parametrize("hour_writes", [False, True])
def test_at_the_model_s_own_boundary_no_stored_loop_clears_anything(
    loop: dict[str, Any], hour_writes: bool
) -> None:
    """Pinned: haiku5 is sent exactly as it was, at either cache lifetime."""
    price = _price()
    result = replay(loop, int(prompt_tier_tokens(price) or 0), price, hour_writes=hour_writes)
    assert not result["cleared"]
    assert not any(request["cleared"] for request in result["sent"])
    assert [r["size"] for r in result["sent"]] == [t["input"] for t in loop["turns"]]


def _boundary_that_clears(loop: dict[str, Any]) -> int | None:
    """A boundary a request of ``loop`` crosses with cited answers enough to come back under it.

    The lowest, over the loop's requests, of the request's size less half of
    what its cited answers weigh; ``None`` where no request holds a cited
    answer it could clear (the newest turn's answers stay).
    """
    found: list[int] = []
    for index, turn in enumerate(loop["turns"]):
        cited = {c for earlier in loop["turns"][:index] for c in earlier["cites"]}
        weight = sum(
            a[2]
            for earlier in loop["turns"][: max(0, index - 1)]
            for a in earlier["answers"]
            if a[0] in cited
        )
        if weight > 1:
            found.append(turn["input"] - weight // 2)
    return min(found) if found else None


STRESSED = [loop for loop in _loops() if _boundary_that_clears(loop) is not None]


@pytest.mark.parametrize("loop", STRESSED, ids=lambda loop: loop["agent"])
def test_with_a_boundary_the_loop_can_get_under_it_clears_and_every_citation_resolves(
    loop: dict[str, Any],
) -> None:
    result = _check(loop, int(_boundary_that_clears(loop) or 0), priced=False)
    assert result["cleared"]


def test_the_long_loops_are_among_those_that_clear() -> None:
    assert sum(loop["agent"] == "all_tools_reverser_ghidra" for loop in STRESSED) >= 3


def test_a_loop_whose_first_request_is_past_the_boundary_sends_what_it_sent() -> None:
    tier = int(prompt_tier_tokens(_price()) or 0)
    reverser = next(loop for loop in _loops() if loop["agent"] == "all_tools_reverser_ghidra")
    assert reverser["turns"][0]["input"] > tier
    result = replay(reverser, tier, _price())
    assert not result["cleared"]
    assert [r["size"] for r in result["sent"]] == [t["input"] for t in reverser["turns"]]


def test_the_replay_without_clears_is_the_stored_requests() -> None:
    for loop in _loops():
        result = replay(loop, None, _price())
        assert [r["size"] for r in result["sent"]] == [t["input"] for t in loop["turns"]]
