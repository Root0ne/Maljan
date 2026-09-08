"""A generic agent's input is the static sample context, not a bare sandbox slice.

Live-verification defect L1 (2026-09-06): a ``generic`` agent definition
(``strings``, bound to an r2 MCP server) ran in a live job and ended with
status ``no_data`` and zero claims. ``make_analyst_node`` chose a generic
role's input the same way it chooses ``dynamic``/``network``'s — a sandbox
slice from ``load_sandbox_data_for_agent`` — and with the mock sandbox
carrying no report for the sample, the loader fell through to its own
"No <type> data available" placeholder for a data type (the agent's own key)
the file loader has no fixture for. ``_is_placeholder_only`` then treated
that placeholder as "nothing to analyse" and the analyst node skipped the
agent, in both the first pass and every revision round.

The controller's ruling: a generic agent's input is the static sample
context the static role receives (sample path plus sample-profile text,
built through the same helper and the same per-provider mirror path lookup
the static branch uses), followed by the sandbox slice when one exists.
Because the sample itself always exists, the "no data" guards must never
skip a generic agent — in the first pass or in revision.

Static, dynamic and network are untouched: their branches are not entered by
any of the new generic-role code, and ``TestBuiltinRolesAreUnaffected`` below
pins their behaviour with the same fake-container pattern used for generic to
guard against a regression in a later refactor.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

from maljan.loaders.binary_chunker import TextChunk
from maljan.pipeline.nodes import _is_placeholder_only, make_analyst_node, make_revision_node


def _chunk(content: str) -> TextChunk:
    return TextChunk(
        index=0,
        total=1,
        strategy=None,  # type: ignore[arg-type]
        content=content,
        char_count=len(content),
        token_estimate=len(content) // 4,
        domain="generic",
    )


def _placeholder(data_type: str) -> list[TextChunk]:
    return [_chunk(f"No {data_type} data available for sample abc123.")]


def _isr() -> MagicMock:
    return MagicMock(claims=[], dissent_items=[], to_text_summary=lambda: "")


def _agent(provider_id: str = "ghidra") -> MagicMock:
    agent = MagicMock()
    agent._resolved.static_provider_id = provider_id
    agent.safe_analyze_isr.return_value = _isr()
    agent.safe_analyze_isr_chunked.return_value = _isr()
    agent.get_last_tool_evidence.return_value = []
    return agent


def _container(agent: MagicMock, *, role: str, load_chunked_return: list[TextChunk]) -> MagicMock:
    events: list[tuple[str, dict[str, Any]]] = []
    container = MagicMock()
    container.is_mock = False
    container.event_sink = lambda t, d: events.append((t, d))
    container.get_agent.return_value = agent
    container.agent_role.return_value = role
    container.load_chunked.return_value = load_chunked_return
    container.config.llm.view_decomposition_views = 0
    container._events = events  # test handle
    return container


def _base_state(**overrides: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "file_hash": "abc123",
        "static_sample_path": "/work/mirror/abc123.exe",
    }
    state.update(overrides)
    return state


class TestGenericFirstPassGetsStaticContext:
    def test_no_sandbox_report_still_shows_sample_path_and_header(self) -> None:
        """(a) No sandbox data: the generic agent's data carries the static
        header text and the mirrored sample path, and it is not skipped."""
        agent = _agent()
        container = _container(agent, role="generic", load_chunked_return=_placeholder("strings"))

        node = make_analyst_node("strings", container)
        result = node(_base_state())

        agent.safe_analyze_isr.assert_called_once()
        shown = agent.safe_analyze_isr.call_args[0][0]
        assert "/work/mirror/abc123.exe" in shown
        assert "Live analysis run" in shown
        assert "analyst skipped" not in result["reports"]["strings"]

    def test_with_sandbox_report_carries_both_static_context_and_sandbox_slice(self) -> None:
        """(b) With sandbox data present, the generic agent's data contains
        both the static sample context and the sandbox slice."""
        agent = _agent()
        container = _container(agent, role="generic", load_chunked_return=_placeholder("strings"))
        sandbox_report = {"target": {"sha256": "abc123"}, "network": {}}
        container.load_sandbox_data_for_agent.return_value = [
            _chunk(json.dumps({"marker": "sandbox-slice-here"}))
        ]

        node = make_analyst_node("strings", container)
        node(_base_state(sandbox_report=sandbox_report))

        container.load_sandbox_data_for_agent.assert_called_once_with("strings", sandbox_report)
        agent.safe_analyze_isr_chunked.assert_called_once()
        chunks_arg = agent.safe_analyze_isr_chunked.call_args[0][0]
        contents = [c.content for c in chunks_arg]
        assert any("/work/mirror/abc123.exe" in c for c in contents), (
            "static sample context must survive alongside the sandbox slice"
        )
        assert any("sandbox-slice-here" in c for c in contents), (
            "the sandbox slice must still reach the agent, appended after the static context"
        )

    def test_a_generic_agent_with_no_mirror_and_no_sample_path_is_still_not_skipped(self) -> None:
        """No container mirror and no host sample path: the static-context
        helper degrades to the bare placeholder, exactly like static's own
        carve-out — the guard must still not delete the agent."""
        agent = _agent()
        container = _container(agent, role="generic", load_chunked_return=_placeholder("strings"))

        node = make_analyst_node("strings", container)
        result = node({"file_hash": "abc123"})

        agent.safe_analyze_isr.assert_called_once()
        assert "analyst skipped" not in result["reports"]["strings"]


class TestGenericRevisionIsNotSkipped:
    def test_generic_is_revised_when_the_sandbox_is_empty(self) -> None:
        """(c) In the revision node a generic agent is revised, not skipped,
        when the sandbox is empty (its raw load_chunked slice is a bare
        placeholder, same as it would be live)."""
        import asyncio

        container = MagicMock()
        container.analyst_keys.return_value = ["strings"]
        container.agent_role.side_effect = lambda _n: "generic"
        container.is_mock = False
        container.config.llm.parallel_analysts = False
        container.load_chunked.side_effect = lambda _h, _n: _placeholder("strings")

        agent = _agent()
        agent.safe_revise_isr.return_value = ("strings revised", _isr())
        container.get_agent.return_value = agent

        node = make_revision_node(container)
        state = {
            "file_hash": "abc123",
            "iteration_count": 1,
            "discussion_history": [],
            "reports": {"strings": "round0 report"},
            "isr_reports": {},
        }
        result = asyncio.run(node(state))

        agent.safe_revise_isr.assert_called_once()
        assert result["revised_reports"]["strings"] == "strings revised"


class TestThePlaceholderGuardExemptsGeneric:
    def test_a_lone_placeholder_is_never_a_skip_for_generic(self) -> None:
        placeholder = [_chunk("No strings data available for sample abc123.")]
        assert _is_placeholder_only(placeholder, "generic") is False
        # Unrelated roles are unaffected by the new exemption.
        assert _is_placeholder_only(placeholder, "dynamic") is True
        assert _is_placeholder_only(placeholder, "network") is True


class TestBuiltinRolesAreUnaffected:
    """Regression pin: static/dynamic/network must take the pre-fix branches.

    None of these exercise the new ``role == "generic"`` code path, so their
    chunk selection is exactly what it was before this change.
    """

    def test_dynamic_with_no_sandbox_report_is_skipped_on_a_placeholder(self) -> None:
        agent = _agent()
        container = _container(agent, role="dynamic", load_chunked_return=_placeholder("dynamic"))

        node = make_analyst_node("dynamic", container)
        result = node(_base_state())

        agent.safe_analyze_isr.assert_not_called()
        assert "no dynamic data available" in result["reports"]["dynamic"].lower()

    def test_network_with_a_sandbox_report_takes_only_the_sandbox_slice(self) -> None:
        agent = _agent()
        container = _container(agent, role="network", load_chunked_return=_placeholder("network"))
        container.load_sandbox_data_for_agent.return_value = [_chunk("parsed network trace")]
        sandbox_report = {"network": {"http": []}}

        node = make_analyst_node("network", container)
        node(_base_state(sandbox_report=sandbox_report))

        container.load_sandbox_data_for_agent.assert_called_once_with("network", sandbox_report)
        container.load_chunked.assert_not_called()
        shown = agent.safe_analyze_isr.call_args[0][0]
        assert shown == "parsed network trace"

    def test_static_augmentation_and_path_pinning_are_unchanged(self) -> None:
        agent = _agent(provider_id="r2")
        container = _container(
            agent,
            role="static",
            load_chunked_return=[_chunk(json.dumps({"file": {"sha256": "abc123"}}))],
        )
        state = _base_state(
            static_sample_paths={"r2": "/host/work/abc123.exe"},
        )

        node = make_analyst_node("static_r2", container)
        node(dict(state, sample_path="/tmp/abc123.exe"))

        shown = agent.safe_analyze_isr.call_args[0][0]
        assert "/host/work/abc123.exe" in shown
        assert agent._analysis_file_path == "/host/work/abc123.exe"


# ---------------------------------------------------------------------------
# BUG 11 (live 2026-09-07, S5): the static_qu1cksc0pe tools were handed a bare
# filename. `_augment_static_chunks_with_path` derives the path from the
# provider's mirror lookup, and with the global static provider `none` there
# is no mirror at all — so `analysis_file_path` was never spliced in and the
# only path-shaped thing left in the context was the sample's own name, which
# Qu1cksc0pe then resolved against its own working directory.
#
# The rule: a generic agent's static context always carries an *absolute*
# path — the provider's mirror path when the provider mirrors, otherwise the
# absolute host `sample_path` the state already holds.
# ---------------------------------------------------------------------------


class TestTheGenericContextAlwaysCarriesAnAbsolutePath:
    def _shown(self, state: dict[str, Any], *, provider_id: str) -> str:
        agent = _agent(provider_id)
        container = _container(agent, role="generic", load_chunked_return=_placeholder("qs"))
        node = make_analyst_node("qs", container)
        node(state)
        agent.safe_analyze_isr.assert_called_once()
        return str(agent.safe_analyze_isr.call_args[0][0])

    def test_a_provider_that_mirrors_nothing_falls_back_to_the_host_path(self) -> None:
        """Provider `none`: no mirror, so the absolute host path is what the
        agent must see. This is the live failure."""
        shown = self._shown(
            {"file_hash": "abc123", "sample_path": "/srv/maljan/data/samples/abc123.exe"},
            provider_id="none",
        )
        assert "/srv/maljan/data/samples/abc123.exe" in shown
        assert '"analysis_file_path": "abc123.exe"' not in shown

    def test_the_mirror_path_still_wins_when_the_provider_mirrors(self) -> None:
        """Provider r2: its own mirror path, not the host path — the tools that
        read it are pointed at the copy, not at the operator's corpus."""
        shown = self._shown(
            {
                "file_hash": "abc123",
                "sample_path": "/srv/maljan/data/samples/abc123.exe",
                "static_sample_paths": {"r2": "/srv/maljan/data/samples/r2-work/abc123.exe"},
            },
            provider_id="r2",
        )
        assert "/srv/maljan/data/samples/r2-work/abc123.exe" in shown
        assert '"analysis_file_path": "/srv/maljan/data/samples/abc123.exe"' not in shown

    def test_the_path_it_carries_is_absolute(self) -> None:
        """A relative `sample_path` in state is still resolved before it is
        handed over: a tool that resolves it against its own cwd is exactly the
        failure being fixed."""
        import json as _json
        import re as _re

        shown = self._shown(
            {"file_hash": "abc123", "sample_path": "data/samples/abc123.exe"},
            provider_id="none",
        )
        match = _re.search(r'"analysis_file_path":\s*("(?:[^"\\]|\\.)*")', shown)
        assert match is not None, f"no analysis_file_path in the generic context: {shown[:400]}"
        path = _json.loads(match.group(1))
        assert path.startswith("/"), f"the agent was given a non-absolute path: {path!r}"
        assert path.endswith("data/samples/abc123.exe")

    def test_nothing_is_invented_when_there_is_no_sample_path_at_all(self) -> None:
        """The existing carve-out stays: no mirror and no host path means the
        placeholder passes through, and the agent is still not skipped."""
        agent = _agent("none")
        container = _container(agent, role="generic", load_chunked_return=_placeholder("qs"))
        node = make_analyst_node("qs", container)
        result = node({"file_hash": "abc123"})
        agent.safe_analyze_isr.assert_called_once()
        assert "analyst skipped" not in result["reports"]["qs"]


# ---------------------------------------------------------------------------
# BUG 11, second round (live 2026-09-07, S5c). The chunk JSON *did* carry an
# absolute ``analysis_file_path`` — the class above proves it — and the live
# run still failed: `static_qu1cksc0pe` called every tool with the bare
# filename and Qu1cksc0pe resolved it against its own working directory.
#
# The path reached the *chunk* and stopped there. ``agent._analysis_file_path``
# — the one channel a tool wrapper can read — is assigned inside the
# ``role == "static"`` branch only, so a generic agent's tools had nothing to
# be pinned against.
# ---------------------------------------------------------------------------


class TestAGenericAgentIsPinnedToTheSamplePathToo:
    def _pin(self, state: dict[str, Any], *, provider_id: str) -> Any:
        agent = _agent(provider_id)
        agent._analysis_file_path = "/stale/from/a/previous/sample.exe"
        container = _container(agent, role="generic", load_chunked_return=_placeholder("qs"))
        node = make_analyst_node("static_qu1cksc0pe", container)
        node(state)
        return agent._analysis_file_path

    def test_the_provider_that_mirrors_nothing_pins_the_absolute_host_path(self) -> None:
        """The live S5c state shape: global provider `none`, an r2 mirror that
        belongs to a *different* agent, and no global mirror at all."""
        pinned = self._pin(
            {
                "file_hash": "abc123",
                "sample_path": "/srv/maljan/data/samples/abc123.exe",
                "static_sample_path": None,
                "static_sample_paths": {"r2": "/srv/maljan/data/samples/r2-work/abc123.exe"},
            },
            provider_id="none",
        )
        assert pinned == "/srv/maljan/data/samples/abc123.exe"

    def test_a_generic_agent_on_a_mirroring_provider_pins_its_own_mirror(self) -> None:
        pinned = self._pin(
            {
                "file_hash": "abc123",
                "sample_path": "/srv/maljan/data/samples/abc123.exe",
                "static_sample_paths": {"r2": "/srv/maljan/data/samples/r2-work/abc123.exe"},
            },
            provider_id="r2",
        )
        assert pinned == "/srv/maljan/data/samples/r2-work/abc123.exe"

    def test_a_stale_pin_from_the_previous_sample_is_cleared(self) -> None:
        """Agents are cached across samples; a pin that cannot be recomputed
        must become None rather than point at yesterday's file."""
        assert self._pin({"file_hash": "abc123"}, provider_id="none") is None
