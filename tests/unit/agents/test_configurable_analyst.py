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


# ---------------------------------------------------------------------------
# BUG 11, second round (live 2026-09-07, S5c). `static_qu1cksc0pe` — a generic
# agent whose static provider resolved to `none` — was handed a chunk whose
# JSON carried an absolute ``analysis_file_path``, and called every one of its
# MCP tools with the *bare filename* instead: {"file_path": "<sha>.exe"}.
# Qu1cksc0pe resolved that against its own working directory and reported
# "File not found: /home/user/tools/Qu1cksc0pe/<sha>.exe".
#
# The static role has never had this problem because its human turn opens with
# an explicit "use the one above verbatim" line. A generic agent's prompt is
# the operator's own text and says nothing about paths, so the framework — not
# the operator — has to say it, and has to catch the model when it says it
# anyway. Two layers, in that order.
# ---------------------------------------------------------------------------

_PATH = "/srv/maljan/data/samples/abc123.exe"
_CHUNK = (
    '{\n  "note": "Live analysis run",\n  "sha256": "abc123",\n'
    f'  "analysis_file_path": "{_PATH}"\n}}'
)


def _human_of_last_call() -> str:
    return str(_Recording.seen[-1][1]["content"])


class TestTheSamplePathIsStatedExplicitly:
    def test_the_header_names_the_absolute_path_when_the_chunk_carries_one(self):
        agent = _agent()
        agent.analyze(_CHUNK)
        human = _human_of_last_call()
        assert _PATH in human
        head = human.split(_CHUNK)[0]
        assert _PATH in head, "the path must be hoisted ABOVE the data, not left inside the JSON"
        assert "exactly" in head.lower()

    def test_the_pinned_path_is_used_when_the_data_carries_no_json(self):
        """A non-head chunk has no JSON; the pin set by the analyst node is
        what keeps every chunk of a chunked run pointed at the same file."""
        agent = _agent()
        agent._analysis_file_path = _PATH
        agent.analyze("plain text chunk with no path in it")
        assert _PATH in _human_of_last_call()

    def test_nothing_is_prepended_when_no_path_is_known(self):
        """The pre-fix prompt is preserved byte-for-byte when there is no
        path to state — an operator's agent that never touches a file is not
        given a line about one."""
        agent = _agent()
        agent.analyze("EVIDENCE-BLOB")
        assert _human_of_last_call() == "EVIDENCE-BLOB"

    def test_the_isr_run_states_the_path_as_well(self):
        agent = _agent()
        agent._analysis_file_path = _PATH
        agent.analyze_isr("EVIDENCE-BLOB")
        assert _PATH in _human_of_last_call()

    def test_a_revision_round_states_the_path_as_well(self):
        agent = _agent()
        agent._analysis_file_path = _PATH
        agent.revise_isr(_CHUNK, "OWN", {}, "F", revision_round=1)
        assert any(_PATH in str(m["content"]) for m in _Recording.seen[-1])


class TestABareFilenameToolArgIsRewritten:
    """Belt and braces: a small local model told the path will still send the
    name. The framework rewrites it before the call rather than letting a tool
    resolve it against a working directory that is not ours."""

    def _agent_with_recording_tool(self):
        """A tool with a real ``args_schema``, as every MCP tool in this repo has.

        The guard rebuilds the tool around its schema, so a schema-less stub
        would exercise a path no live tool takes — and, since the guard now
        declines to rebuild one, would not be wrapped at all.
        """
        calls: list[dict[str, Any]] = []

        def _scan(file_path: str = "", query: str = "") -> str:
            calls.append({k: v for k, v in (("file_path", file_path), ("query", query)) if v})
            return "scanned"

        tool = StructuredTool.from_function(
            func=_scan,
            name="analyze_file",
            description="analyze a file",
        )
        agent = _agent(tools=[tool])
        agent._analysis_file_path = _PATH
        return agent, calls

    def _invoke(self, agent: ConfigurableAnalyst, args: dict[str, Any]) -> Any:
        tool = agent.pinned_tools()[0]
        return tool.func(**args)  # type: ignore[misc]

    def test_a_bare_filename_equal_to_the_sample_name_becomes_the_absolute_path(self):
        agent, calls = self._agent_with_recording_tool()
        self._invoke(agent, {"file_path": "abc123.exe"})
        assert calls == [{"file_path": _PATH}]

    def test_the_rewrite_is_logged(self, caplog):
        import logging

        agent, _calls = self._agent_with_recording_tool()
        with caplog.at_level(logging.WARNING):
            self._invoke(agent, {"file_path": "abc123.exe"})
        logged = [r.getMessage() for r in caplog.records]
        assert any("abc123.exe" in m and _PATH in m for m in logged)

    def test_a_path_the_model_got_right_is_left_alone(self):
        agent, calls = self._agent_with_recording_tool()
        self._invoke(agent, {"file_path": _PATH})
        assert calls == [{"file_path": _PATH}]

    def test_an_unrelated_filename_is_never_rewritten(self):
        """Only the sample's own name is a known mistake. A tool asked to read
        a dropped file, a rule file or an output the agent just wrote must
        keep the name it was given."""
        agent, calls = self._agent_with_recording_tool()
        self._invoke(agent, {"file_path": "rules.yar"})
        assert calls == [{"file_path": "rules.yar"}]

    def test_a_non_path_argument_is_never_rewritten(self):
        agent, calls = self._agent_with_recording_tool()
        self._invoke(agent, {"query": "abc123.exe"})
        assert calls == [{"query": "abc123.exe"}]

    def test_a_relative_path_ending_in_the_sample_name_is_not_touched(self):
        """The failure is a *bare* name resolved against a foreign cwd. A model
        that supplied a directory meant that directory."""
        agent, calls = self._agent_with_recording_tool()
        self._invoke(agent, {"file_path": "dropped/abc123.exe"})
        assert calls == [{"file_path": "dropped/abc123.exe"}]

    def test_the_rewrite_survives_the_schema_bound_invoke_path(self):
        """The wrapped tool is what the ReAct loop actually calls, and it calls
        it through ``invoke`` against the rebuilt schema, not through ``func``."""
        agent, calls = self._agent_with_recording_tool()
        assert agent.pinned_tools()[0].invoke({"file_path": "abc123.exe"}) == "scanned"
        assert calls == [{"file_path": _PATH}]

    def test_with_no_pin_the_tools_are_handed_through_unwrapped(self):
        def _scan(file_path: str = "") -> str:
            return "scanned"

        tool = StructuredTool.from_function(func=_scan, name="analyze_file", description="d")
        agent = _agent(tools=[tool])
        assert agent.pinned_tools() == [tool]

    def test_a_tool_with_no_args_schema_is_left_exactly_as_it_is(self):
        """The guard rebuilds a tool around its schema. With none to rebuild
        around, wrapping would hand the model a tool that binds badly — worse
        than the bare-filename call it is there to prevent."""

        def _scan(**kwargs: Any) -> str:
            return "scanned"

        tool = StructuredTool.from_function(
            func=_scan, name="analyze_file", description="d", infer_schema=False
        )
        assert tool.args_schema is None
        agent = _agent(tools=[tool])
        agent._analysis_file_path = _PATH
        assert agent.pinned_tools() == [tool]

    def test_a_free_text_input_argument_is_no_longer_treated_as_a_path(self):
        """``input`` names free text as often as it names a file; a lookup tool
        asked about the sample by name must keep the name it was given."""
        from maljan.agents.configurable_analyst import _is_path_argument

        assert _is_path_argument("input") is False
        assert _is_path_argument("query") is False
        assert all(_is_path_argument(n) for n in ("file_path", "path", "binary", "target"))
