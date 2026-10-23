"""What each agent's requests were made of, measured as they are sent.

One ``InputMeter`` lives on the ``ServiceContainer`` (one per analysis run),
beside the token ledger. An agent tells it about every request it is about to
send: a tool loop's turns, from the hook every turn already goes through, and
each single call outside a loop (a revision, a validation retry, a drops
question, a salvage). The report node reads it into ``run_summary.efficiency``.

A request is split into the parts it is made of (:data:`PARTS`), each measured
in **characters**, always: no provider reports how many tokens each part of a
prompt took, only the prompt's total. That total, where the provider reported
it, is kept beside the parts as the provider's own figure, with the number of
requests that reported one, and is never apportioned among them.

The run fingerprint is not read from here: it hashes the job's setup, never
what a run sent (``analysis.setup_prompts``). This module gives it the digest
and the tool-definition digests.

Nothing here changes what is sent: the meter reads the messages a request
carries and keeps counts. Recording never raises — telemetry must not break
analysis.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

# The parts of a request, in the order a report lists them.
#
# ``system_prompt``    the system message.
# ``task``             what the first human turn carries besides the parts below:
#                      the instruction and the data the agent is given.
# ``pack``             the triage pack, where the first human turn carries it.
# ``run_state``        the run-state block the platform attaches, and the earlier
#                      blocks a provider sends again.
# ``tool_answers``     the tool answers the conversation holds.
# ``peer_reports``     the other analysts' reports a revision carries.
# ``retries``          every human turn after the first model answer: a
#                      validation retry, a drops question, a nudge, and any
#                      notice the platform sends as a human turn.
# ``own_turns``        the agent's own earlier turns and answers, sent again.
# ``tool_definitions`` the definitions of the tools a loop's request is bound to.
PARTS: tuple[str, ...] = (
    "system_prompt",
    "task",
    "pack",
    "run_state",
    "tool_answers",
    "peer_reports",
    "retries",
    "own_turns",
    "tool_definitions",
)

# The kind of a row that sums a tool loop's turns; a single call's row is
# kind by the name its caller gives the call ("revision", "validation retry").
TOOL_LOOP = "tool loop"


def _text_of(content: Any) -> str:
    """A message's content as text: a string as it is, a block list's text parts joined."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out: list[str] = []
        for part in content:
            if isinstance(part, str):
                out.append(part)
            elif isinstance(part, Mapping) and isinstance(part.get("text"), str):
                out.append(part["text"])
        return "".join(out)
    return str(content or "")


def _plain_measure(message: Any) -> int:
    return len(str(getattr(message, "content", "") or ""))


def _run_state_chars(message: Any) -> int:
    """The characters of the run-state block the platform attached to ``message``, or 0.

    Recognised by the note the platform leaves on the message
    (``anthropic_history.RUN_STATE_ATTACHED``), never by its markers, which
    any text can carry; measured with the separator it was attached with.
    """
    from maljan.llm.anthropic_history import RUN_STATE_ATTACHED

    block = (getattr(message, "response_metadata", None) or {}).get(RUN_STATE_ATTACHED)
    if not isinstance(block, str) or not block:
        return 0
    content = getattr(message, "content", None)
    if isinstance(content, str):
        from maljan.pipeline.run_state import without_run_state_tail

        if not content.endswith(block):
            return 0
        return len(content) - len(without_run_state_tail(content, block))
    if isinstance(content, list) and content:
        last = content[-1]
        if isinstance(last, Mapping) and last.get("text") == block:
            return len(block)
    return 0


def _found(texts: Iterable[str], within: str) -> int:
    """The characters of each non-empty text of ``texts`` that ``within`` carries."""
    return sum(len(text) for text in texts if text and text in within)


def request_parts(
    messages: Sequence[Any],
    *,
    measure: Callable[[Any], int] | None = None,
    pack: str = "",
    peers: Sequence[str] = (),
    own: Sequence[str] = (),
    definitions: int = 0,
    replayed: int = 0,
) -> dict[str, int]:
    """``messages``, one request, split into :data:`PARTS`, in characters.

    ``measure`` is the size of one message as the caller's budget measures it
    (an assistant turn's tool requests included); the parts of a message add
    up to it. ``pack`` is the triage pack text, ``peers`` the peer reports and
    ``own`` the agent's own earlier answers the request embeds in a human
    turn: each is counted where the turn carries it, and what is left of the
    first human turns is the task. ``definitions`` is what the tool
    definitions weigh with this request and ``replayed`` the earlier run-state
    blocks a provider sends again.
    """
    size = measure or _plain_measure
    parts = dict.fromkeys(PARTS, 0)
    answered = False
    for message in messages:
        kind = str(getattr(message, "type", "") or "")
        total = max(0, int(size(message)))
        if kind == "system":
            parts["system_prompt"] += total
            continue
        if kind == "ai":
            parts["own_turns"] += total
            answered = True
            continue
        block = min(total, _run_state_chars(message))
        parts["run_state"] += block
        rest = total - block
        if kind == "tool":
            parts["tool_answers"] += rest
            continue
        if answered:
            parts["retries"] += rest
            continue
        text = _text_of(getattr(message, "content", ""))
        for part, texts in (("pack", (pack,)), ("peer_reports", peers), ("own_turns", own)):
            taken = min(rest, _found(texts, text))
            parts[part] += taken
            rest -= taken
        parts["task"] += rest
    parts["tool_definitions"] += max(0, int(definitions))
    parts["run_state"] += max(0, int(replayed))
    return parts


def digest(text: str) -> str:
    """The sha256 of ``text``, hex."""
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def tool_digests(tools: Iterable[Any]) -> dict[str, str]:
    """Each tool's definition as a request carries it, by the tool's name, as a digest.

    The OpenAI-compatible definition, the one ``context_window.tool_definition_chars``
    measures, serialised with its keys in order. A tool that cannot be
    described is left out.
    """
    from langchain_core.utils.function_calling import convert_to_openai_tool

    out: dict[str, str] = {}
    for tool in tools:
        try:
            definition = convert_to_openai_tool(tool)
            text = json.dumps(definition, sort_keys=True, ensure_ascii=False, default=str)
        except Exception:  # noqa: BLE001 — a definition is never worth a lost loop
            continue
        name = str(getattr(tool, "name", "") or definition.get("function", {}).get("name", ""))
        out[name] = digest(text)
    return out


def _new_row(agent: str, stage: str, kind: str) -> dict[str, Any]:
    return {
        "agent": agent,
        "stage": stage,
        "kind": kind,
        "requests": 0,
        "parts": dict.fromkeys(PARTS, 0),
        "reported_requests": 0,
        "input_tokens": 0,
    }


class InputMeter:
    """Thread-safe record of what one run's requests were made of, per agent loop."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # One row per tool loop, in the order loops started, and one per
        # agent, stage and kind of single call, in the order first made.
        self._rows: list[dict[str, Any]] = []
        # The open tool loops, by agent and loop object: the loop's own
        # budget, held until the loop is closed so its identity is not reused.
        self._loops: dict[tuple[str, int], tuple[Any, dict[str, Any]]] = {}
        self._calls: dict[tuple[str, str, str], dict[str, Any]] = {}

    def request(
        self,
        agent: str,
        parts: Mapping[str, int],
        *,
        stage: str = "",
        kind: str = TOOL_LOOP,
        loop: Any = None,
    ) -> dict[str, Any] | None:
        """One request about to be sent; the row it was counted on (for :meth:`answered`).

        ``loop`` is the tool loop the request is a turn of — its turns are
        summed on one row until :meth:`close` — or ``None`` for a single call,
        summed with the agent's other calls of the same ``kind`` and stage.
        """
        try:
            with self._lock:
                if loop is not None:
                    held = self._loops.get((agent, id(loop)))
                    if held is None or held[0] is not loop:
                        row = _new_row(agent, stage, TOOL_LOOP)
                        self._rows.append(row)
                        self._loops[(agent, id(loop))] = (loop, row)
                    else:
                        row = held[1]
                else:
                    key = (agent, stage, kind)
                    found = self._calls.get(key)
                    if found is None:
                        found = _new_row(agent, stage, kind)
                        self._rows.append(found)
                        self._calls[key] = found
                    row = found
                row["requests"] += 1
                for part in PARTS:
                    row["parts"][part] += max(0, int(parts.get(part, 0) or 0))
                return row
        except Exception:  # noqa: BLE001 — recording never raises
            return None

    def answered(self, row: dict[str, Any] | None, usage: Mapping[str, Any] | None) -> None:
        """A single call's answer: its reported input tokens onto ``row``, where reported."""
        if row is None or not isinstance(usage, Mapping):
            return
        try:
            tokens = int(usage.get("input_tokens") or 0)
            with self._lock:
                row["reported_requests"] += 1
                row["input_tokens"] += max(0, tokens)
        except Exception:  # noqa: BLE001 — recording never raises
            return

    def close(self, agent: str, loop: Any, usages: Iterable[Mapping[str, Any] | None]) -> None:
        """A tool loop ended: its turns' reported input tokens onto its row, and the row closed.

        ``usages`` is each model turn's reported usage (``token_ledger.turn_usage``),
        ``None`` for a turn whose provider reported none.
        """
        try:
            with self._lock:
                held = self._loops.pop((agent, id(loop)), None)
                if held is None or held[0] is not loop:
                    return
                row = held[1]
                for usage in usages:
                    if isinstance(usage, Mapping):
                        row["reported_requests"] += 1
                        row["input_tokens"] += max(0, int(usage.get("input_tokens") or 0))
        except Exception:  # noqa: BLE001 — recording never raises
            return

    def rows(self) -> list[dict[str, Any]]:
        """A plain copy of every row, in order; ``input_tokens`` only where a request reported."""
        with self._lock:
            out: list[dict[str, Any]] = []
            for row in self._rows:
                copy = {**row, "parts": dict(row["parts"])}
                if not copy["reported_requests"]:
                    copy.pop("input_tokens", None)
                out.append(copy)
            return out
