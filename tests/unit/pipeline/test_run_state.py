"""The run-state block is derived, regenerated, and sent last.

It travels between two markers at the end of a request's last message.
Framing a conversation twice leaves one block, the newer, at the end; the
per-turn refresher regenerates it on the latest turn, so every earlier byte of
the request is the previous turn's; and the forced-synthesis trim, which drops
whole tool exchanges to fit a budget, keeps the system turn and the first
human turn, where the pack is.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from maljan.agents.base_agent import BaseAnalyst, _trim_for_synthesis, frame_messages
from maljan.pipeline.run_state import (
    RUN_STATE_BEGIN,
    RUN_STATE_END,
    render_run_state,
    with_run_state,
)
from maljan.pipeline.triage_pack import PACK_HEADING, PIPELINE
from maljan.schemas.evidence import build_entry, format_entry_id


def _row(tool: str, payload: Any, seq: int, *, ok: bool = True, agent: str = PIPELINE) -> dict:
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent=agent,
        tool=tool,
        args={},
        server=PIPELINE,
        output=json.dumps(payload) if not isinstance(payload, str) else payload,
        ok=ok,
        error=None if ok else str(payload),
    ).model_dump(mode="json")


STATE: dict[str, Any] = {
    "file_hash": "c" * 64,
    "file_type": "pe",
    "platform": "windows",
    "file_name": "putty.exe",
    "evidence_ledger": [
        _row("identify_file", {"file_type": "pe", "platform": "windows", "size": 1_633_792}, 1),
        _row("hashes", {"sha256": "c" * 64, "md5": "d" * 32}, 2),
        _row(
            "signing_info",
            {
                "authenticode": {"present": True, "subject": "Simon Tatham"},
                "apk": {"present": False},
                "macho": {"present": False},
            },
            3,
        ),
        _row("capa", "capa produced no result within its budget", 4, ok=False),
        _row(
            "check_hash",
            "Hash c not found in VirusTotal database.",
            5,
        ),
        _row("pe_info", {"machine": 332}, 6, agent="static"),
    ],
    "stage_results": {
        "triage_pack": {"ran": True, "reason": ""},
        "network": {"ran": False, "reason": "condition not met: has_pcap"},
    },
}


class TestWhatTheBlockSays:
    def test_it_names_the_sample_the_identity_the_signature_and_the_reputation(self) -> None:
        lines = render_run_state(STATE).splitlines()
        assert lines[0] == f"sample: {'c' * 64}, pe windows, submitted as putty.exe"
        assert lines[1].startswith("[ev_0001] identity: pe windows, 1,633,792 bytes")
        assert lines[2] == f"[ev_0002] hashes: sha256 {'c' * 64}, md5 {'d' * 32}"
        assert lines[3] == "[ev_0003] signature: authenticode present (subject Simon Tatham)"
        assert lines[4].startswith("[ev_0005] reputation: ")

    def test_it_says_which_stages_ran_and_why_one_did_not(self) -> None:
        text = render_run_state(STATE)
        assert "stages: triage_pack ran; network skipped (condition not met: has_pcap)" in text

    def test_it_counts_the_ledger_and_names_the_failed_tools(self) -> None:
        text = render_run_state(STATE)
        assert "ledger: 6 entries (ev_0001–ev_0006), 5 from the triage pack" in text
        assert "tools failed: capa (pipeline)" in text

    def test_the_budget_line_is_there_only_when_a_budget_is_given(self) -> None:
        assert "budget" not in render_run_state(STATE)
        assert render_run_state(STATE, steps_left=7, seconds_left=91.9).endswith(
            "budget remaining: 7 model turns, 91 s"
        )

    def test_an_empty_state_renders_nothing(self) -> None:
        assert render_run_state({}) == ""

    def test_a_long_pack_line_is_cut_here_although_the_pack_keeps_it_whole(self) -> None:
        long_subject = "S" * 400
        state = {
            **STATE,
            "evidence_ledger": [
                _row(
                    "signing_info",
                    {
                        "authenticode": {"present": True, "subject": long_subject},
                        "apk": {"present": False},
                        "macho": {"present": False},
                    },
                    1,
                )
            ],
        }
        (line,) = [ln for ln in render_run_state(state).splitlines() if "signature" in ln]
        assert len(line) == 240 and line.endswith("…")

    def test_the_block_is_facts_and_names_no_verdict(self) -> None:
        text = render_run_state(STATE).lower()
        for word in ("malicious", "benign", "suspicious", "likely", "probably"):
            assert word not in text, word


class TestOneBlockPerPrompt:
    def test_a_block_is_appended_once_and_replaced_after_that(self) -> None:
        system = with_run_state("You are an analyst.", "sample: a")
        assert system == f"You are an analyst.\n\n{RUN_STATE_BEGIN}\nsample: a\n{RUN_STATE_END}"
        again = with_run_state(system, "sample: b\nbudget remaining: 3 model turns")
        assert again.count(RUN_STATE_BEGIN) == 1
        assert "sample: a" not in again
        assert again.endswith(f"sample: b\nbudget remaining: 3 model turns\n{RUN_STATE_END}")

    def test_an_empty_body_takes_the_block_out(self) -> None:
        system = with_run_state("You are an analyst.", "sample: a")
        assert with_run_state(system, "") == "You are an analyst."
        assert with_run_state("You are an analyst.", "") == "You are an analyst."

    def test_framing_twice_leaves_one_block_and_one_pack(self) -> None:
        messages = [SystemMessage(content="sys"), HumanMessage(content="task")]
        once = frame_messages(messages, facts_block=f"{PACK_HEADING}\n[ev_0001] x", run_state="s1")
        twice = frame_messages(once, facts_block=f"{PACK_HEADING}\n[ev_0001] x", run_state="s2")
        assert len(twice) == 2
        assert twice[0].content == "sys"
        assert str(twice[-1].content).endswith(f"task\n\n{RUN_STATE_BEGIN}\ns2\n{RUN_STATE_END}")
        assert sum(str(m.content).count(RUN_STATE_BEGIN) for m in twice) == 1
        assert str(twice[1].content).count(PACK_HEADING) == 1
        assert str(twice[1].content).startswith(PACK_HEADING)

    def test_empty_blocks_leave_the_conversation_byte_for_byte(self) -> None:
        messages = [SystemMessage(content="sys"), HumanMessage(content="task")]
        framed = frame_messages(messages)
        assert [m.content for m in framed] == ["sys", "task"]


class TestTheBlockSurvivesTrimming:
    def _conversation(self, tool_turns: int) -> list[Any]:
        head = frame_messages(
            [SystemMessage(content="You are an analyst."), HumanMessage(content="Analyse it.")],
            facts_block=f"{PACK_HEADING}\n[ev_0001] identity: pe windows",
            run_state="sample: c\nledger: 1 entries",
        )
        rest: list[Any] = []
        for index in range(tool_turns):
            rest.append(
                AIMessage(
                    content="",
                    tool_calls=[{"name": "strings", "args": {"path": "/s"}, "id": f"c{index}"}],
                )
            )
            rest.append(ToolMessage(content="x" * 2000, tool_call_id=f"c{index}"))
        return [*head, *rest]

    def test_the_trim_drops_tool_exchanges_and_keeps_both_blocks(self) -> None:
        msgs = self._conversation(10)
        trimmed = _trim_for_synthesis(msgs, 5000)
        assert len(trimmed) < len(msgs)
        assert str(trimmed[0].content) == "You are an analyst."
        assert str(trimmed[1].content).startswith(PACK_HEADING)


class _Analyst(BaseAnalyst):
    def __init__(self) -> None:
        super().__init__(llm=None, name="static")  # type: ignore[arg-type]

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


class TestThePerTurnRefresh:
    def test_the_first_turn_reads_the_whole_budget_and_each_agent_step_takes_one(self) -> None:
        """A step is a model turn: the framing and the tool results cost nothing."""
        import re
        import time

        agent = _Analyst()
        agent.run_state_block = "sample: c"
        refresh = agent._run_state_refresher(max_steps=10, timeout=600.0, started=time.monotonic())
        opening = [SystemMessage(content="sys"), HumanMessage(content="t")]
        first = refresh({"messages": opening})
        assert first[0] == opening[0]
        assert str(first[1].content).startswith("t\n\n" + RUN_STATE_BEGIN)
        line = re.search(r"budget remaining: (\d+) model turns, (\d+) s", str(first[-1].content))
        assert line is not None
        # recursion_limit=10 is five model turns: a turn that calls a tool
        # costs two graph steps, so the first turn reads half the limit.
        assert int(line.group(1)) == 5
        assert 590 <= int(line.group(2)) <= 600
        later = refresh(
            {
                "messages": [
                    *opening,
                    AIMessage(content="", tool_calls=[{"name": "t", "args": {}, "id": "1"}]),
                    ToolMessage(content="r", tool_call_id="1"),
                    AIMessage(content="b"),
                    HumanMessage(content="go on"),
                ]
            }
        )
        # One tool round (two steps) and one plain assistant turn (one step)
        # leave seven of ten, which is four model turns at most.
        assert "budget remaining: 4 model turns" in str(later[-1].content)
        assert sum(str(m.content).count(RUN_STATE_BEGIN) for m in later) == 1

    def test_a_real_executor_calls_the_refresher_before_the_model(self) -> None:
        """The whole mechanism rides on langgraph's ``prompt`` hook; this pins it."""
        import time

        from langchain_core.language_models.chat_models import BaseChatModel
        from langchain_core.outputs import ChatGeneration, ChatResult
        from langgraph.prebuilt import create_react_agent

        seen: list[list[Any]] = []

        class _Model(BaseChatModel):
            def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any):
                seen.append(list(messages))
                return ChatResult(generations=[ChatGeneration(message=AIMessage(content="ok"))])

            @property
            def _llm_type(self) -> str:
                return "fake"

            def bind_tools(self, tools: Any, **_: Any) -> Any:
                return self

        agent = _Analyst()
        agent.run_state_block = "sample: c"
        executor = create_react_agent(
            _Model(),
            [],
            prompt=agent._run_state_refresher(
                max_steps=10, timeout=600.0, started=time.monotonic()
            ),
        )
        executor.invoke({"messages": [SystemMessage(content="sys"), HumanMessage(content="t")]})
        assert seen
        assert str(seen[0][0].content) == "sys"
        block = str(seen[0][-1].content)
        assert RUN_STATE_BEGIN in block and "budget remaining: 5 model turns" in block

    def test_an_agent_without_a_block_hands_the_turn_back_untouched(self) -> None:
        agent = _Analyst()
        refresh = agent._run_state_refresher(max_steps=10, timeout=600.0, started=0.0)
        messages = [SystemMessage(content="sys"), HumanMessage(content="t")]
        assert [m.content for m in refresh({"messages": messages})] == ["sys", "t"]


class TestNotRunIsNotFailed:
    def test_a_skipped_lookup_is_not_listed_as_a_failed_tool(self) -> None:
        state = {
            **STATE,
            "evidence_ledger": [
                *STATE["evidence_ledger"],
                _row("reputation", "not run: core.triage.reputation is off", 9, ok=False),
            ],
        }
        text = render_run_state(state)
        assert "tools failed: capa (pipeline)" in text
        assert "reputation" not in text.split("tools failed:")[1].splitlines()[0]
