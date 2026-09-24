"""No prompt states a tool set that differs from the list its request carries.

A live run sent the static analyst 36 tools — analysis, knowledge and
reputation — under a provider fragment that said "You have no analysis tools
in this configuration". The model believed the fragment, answered in one turn
and called nothing. The sentence about tools is now built from the list, and
this guard holds every built-in agent to it under every provider: through the
real composition (``aresolve_agent`` for what resolution says, ``prompt_for``
for what an analyst sends), for the list resolution computes, for that list
with the provider's own tools added the way the analyst adds them, and for the
empty list of a tools-free call.

Two rules. A prompt never says there are no tools while the list holds some,
and always says so when it holds none. And a prompt never names a tool family
the list does not hold: a decompiler, a provider's own tools by name, a
sandbox's own server, a registry server, the team's ``ask_`` tools, the sandbox
report's tools.

Only the tool servers are stood in for, by a registry that hands back stamped
tools the way the real one does, so no subprocess starts; everything else —
the settings, the definitions, the profiles, the providers — is the shipped one.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Sequence
from typing import Any

import pytest

from maljan.agents.composition import aresolve_agent, prompt_for
from maljan.agents.prompt_fragments import (
    NO_TOOLS_STATEMENT,
    PROVIDER_FAMILY,
    SANDBOX_FAMILY,
    TEAM_FAMILY,
    has_decompiler,
    tool_families,
    tool_names,
)
from maljan.core.config import ALL_SERVERS, Settings
from maljan.core.container import ServiceContainer
from maljan.providers.registry import discover_providers, sandbox_provider_ids, static_provider_ids

discover_providers()

# The agents whose prompt resolution composes. The reporter has none: it is
# resolved nowhere, and ``builtin_prompt`` refuses its role.
PROMPTED_ROLES = frozenset({"static", "dynamic", "network", "judge", "generic", "lead"})

# Sentences every earlier version of a prompt used to say there were no tools.
LEGACY_NO_TOOLS = ("You have no analysis tools", "no tools in this configuration")

# What a provider's own tools are called, for the providers that have any. The
# fragments name these; a list that holds them is the list the analyst sends
# once its provider attached.
PROVIDER_TOOLS: dict[str, tuple[str, ...]] = {
    "ghidra": ("load_program", "get_current_program_info", "decompile_function", "get_xrefs_to"),
    "r2": ("open_file", "analyze", "list_functions", "decompile_function", "xrefs_to"),
    "generic_mcp": ("operator_tool",),
    "cape2": ("get_cuckoo_status", "search_task", "submit_file", "get_task_report"),
}

# Families a prompt can name, each with the phrases that name it and what the
# list must hold for the prompt to say it.
_FAMILY_MARKERS: tuple[tuple[str, tuple[str, ...], Any], ...] = (
    (
        "a decompiler",
        ("decompile, xrefs", "`decompile_function", "You can decompile functions"),
        has_decompiler,
    ),
    (
        "Ghidra's own tools",
        ("`load_program", "`get_current_program_info`", "`detect_malware_behaviors`"),
        lambda tools: "load_program" in tool_names(tools),
    ),
    (
        "radare2's own tools",
        ("`open_file`", "`list_functions`"),
        lambda tools: "open_file" in tool_names(tools),
    ),
    (
        "the CAPE server",
        ("`get_cuckoo_status`", "`get_task_report", "`submit_file"),
        lambda tools: "get_cuckoo_status" in tool_names(tools),
    ),
    (
        "the sandbox report's tools",
        ("the job's sandbox report",),
        lambda tools: SANDBOX_FAMILY in tool_families(tools),
    ),
    (
        "the team's ask tools",
        ("one `ask_<agent>` tool each",),
        lambda tools: TEAM_FAMILY in tool_families(tools),
    ),
    (
        "a provider's own tools",
        ("static provider;", "static provider and", "static provider,", "own tool server"),
        lambda tools: PROVIDER_FAMILY in tool_families(tools),
    ),
)

_SERVER_RE = re.compile(r"the `([^`]+)` server")


class _Tool:
    """A tool as the registry hands it over: a name, stamped with its server."""

    def __init__(self, name: str, server: str = "") -> None:
        self.name = name
        self.metadata = {"maljan_server": server} if server else {}


class _Registry:
    """The job's tool servers, answering without starting one.

    Honours what the real registry honours: a server is bound to an agent by
    its ``agents`` list or named by a reference, and the profile's exclusions
    — ``*`` among them — withhold it.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.degradation_reasons: list[str] = []

    @staticmethod
    def _tools(server: str) -> list[Any]:
        return [_Tool(f"{server}_lookup", server), _Tool(f"{server}_report", server)]

    def tools_for(
        self, key: str, job_key: str, exclude: str = "", seen: Any = None, **_: Any
    ) -> tuple[list[Any], list[str]]:
        withheld = {name for name in exclude.split(",") if name}
        if ALL_SERVERS in withheld:
            return [], []
        tools: list[Any] = []
        for name, server in self.settings.mcp.servers.items():
            if server.enabled and key in server.agents and name not in withheld:
                tools.extend(self._tools(name))
        return tools, []

    def tools_for_ref(
        self, ref: Any, job_key: str, seen: Any = None, **_: Any
    ) -> tuple[list[Any], list[str]]:
        server = self.settings.mcp.servers.get(str(ref.server))
        if server is None or not server.enabled:
            return [], [f"server {ref.server} is not enabled"]
        return self._tools(str(ref.server)), []

    async def atools_for(self, *args: Any, **kwargs: Any) -> tuple[list[Any], list[str]]:
        return self.tools_for(*args, **kwargs)

    async def atools_for_ref(self, *args: Any, **kwargs: Any) -> tuple[list[Any], list[str]]:
        return self.tools_for_ref(*args, **kwargs)


def _container(static_provider: str, sandbox_provider: str, profile: str) -> ServiceContainer:
    settings = Settings(_env_file=None)
    settings.static.provider = static_provider
    settings.sandbox.provider = sandbox_provider
    settings.sandbox.cape2.mcp.enabled = True
    # The REST adapter refuses to build without an endpoint; nothing is sent.
    settings.sandbox.rest.base_url = "http://sandbox.invalid"
    settings.agents.profile = profile
    container = ServiceContainer(settings, mock=True)
    container.sample_format = ("pe", "windows")
    registry = _Registry(settings)
    container.get_server_registry = lambda: registry  # type: ignore[method-assign]
    # A mock container answers with the mock sandbox whatever is configured;
    # the guard wants the configured one, built as the registry builds it.
    from maljan.providers.registry import get_sandbox_provider

    sandbox = get_sandbox_provider(settings)
    container.get_sandbox_provider = lambda: sandbox  # type: ignore[method-assign]
    return container


def _provider_tools(container: ServiceContainer, role: str, provider_id: str) -> list[Any]:
    """The tools a built-in role's class adds itself, as it adds them: unstamped."""
    if role == "static":
        provider = container.get_static_provider(provider_id)
        pid = provider.id
    elif role == "dynamic":
        provider = container.get_sandbox_provider()
        pid = provider.id
    else:
        return []
    if not provider.capabilities.provides_tools:
        return []
    return [_Tool(name) for name in PROVIDER_TOOLS.get(pid, ("provider_tool",))]


def _violations(prompt: str, tools: Sequence[Any], *, statement_expected: bool) -> list[str]:
    """Everything ``prompt`` says about tools that ``tools`` does not bear out."""
    found: list[str] = []
    if tools:
        found += [f"says {phrase!r}" for phrase in LEGACY_NO_TOOLS if phrase in prompt]
        if NO_TOOLS_STATEMENT in prompt:
            found.append("says it has no tools")
    elif statement_expected and NO_TOOLS_STATEMENT not in prompt:
        found.append("does not say it has no tools")
    for family, phrases, holds in _FAMILY_MARKERS:
        named = [phrase for phrase in phrases if phrase in prompt]
        if named and not holds(tools):
            found.append(f"names {family} ({named[0]!r})")
    families = set(tool_families(tools))
    for server in _SERVER_RE.findall(prompt):
        if server not in families:
            found.append(f"names the `{server}` server")
    return found


def _cases() -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for profile in ("default", "measurement"):
        for static in static_provider_ids():
            out.append((static, "mock", profile))
        for sandbox in sandbox_provider_ids():
            out.append(("none", sandbox, profile))
    return out


@pytest.mark.parametrize(("static", "sandbox", "profile"), _cases())
def test_no_built_in_agent_is_told_a_tool_set_it_is_not_sent(
    static: str, sandbox: str, profile: str
) -> None:
    container = _container(static, sandbox, profile)
    problems: list[str] = []
    checked = 0
    for key, definition in container.config.agents.definitions.items():
        if definition.role not in PROMPTED_ROLES:
            continue
        resolved = asyncio.run(aresolve_agent(key, container))
        judge = definition.role == "judge"
        own = _provider_tools(container, definition.role, resolved.static_provider_id)

        # What resolution says, against what resolution listed and what the
        # role's class adds to it.
        expected = [*own, *resolved.tools]
        for issue in _violations(resolved.prompt, expected, statement_expected=not judge):
            problems.append(f"{key} resolved: {issue}")

        if judge:
            checked += 1
            continue
        # What the agent sends: with its provider attached, with the attach
        # failed, and on a tools-free call.
        for label, sent in (
            ("with its provider", [*own, *resolved.tools]),
            ("without its provider", list(resolved.tools)),
            ("on a tools-free call", []),
        ):
            prompt = prompt_for(resolved, container, sent)
            for issue in _violations(prompt, sent, statement_expected=True):
                problems.append(f"{key} {label}: {issue}")
        checked += 1

    assert checked >= 5, "the guard checked too few agents to mean anything"
    assert not problems, "\n".join(problems)


def test_the_static_analyst_on_no_provider_is_told_of_the_tools_it_is_sent() -> None:
    """The reported case: provider ``none``, the default definition's three servers."""
    container = _container("none", "mock", "default")
    container.config.mcp.servers["virustotal"].enabled = True
    resolved = asyncio.run(aresolve_agent("static", container))

    prompt = prompt_for(resolved, container, resolved.tools)

    assert {"analysis", "knowledge", "virustotal"} <= set(tool_families(resolved.tools))
    assert "You have no analysis tools" not in prompt
    assert NO_TOOLS_STATEMENT not in prompt
    for server in ("analysis", "knowledge", "virustotal"):
        assert f"the `{server}` server" in prompt
    assert "No static provider is attached" in prompt


def test_the_measurement_baseline_is_told_it_has_no_tools() -> None:
    container = _container("ghidra", "mock", "measurement")
    for key in ("static", "dynamic", "network"):
        resolved = asyncio.run(aresolve_agent(key, container))
        assert resolved.tools == []
        assert NO_TOOLS_STATEMENT in prompt_for(resolved, container, [])


class TestTheGuardWouldCatchOne:
    def test_a_no_tools_sentence_beside_a_tool_list(self) -> None:
        prompt = "You have no analysis tools in this configuration."
        assert _violations(prompt, [_Tool("x", "analysis")], statement_expected=True)

    def test_a_decompiler_promise_with_no_decompiler(self) -> None:
        prompt = "You may use tools to gather more information (decompile, xrefs, etc.)."
        assert _violations(prompt, [_Tool("x", "analysis")], statement_expected=False)

    def test_a_server_the_list_does_not_hold(self) -> None:
        prompt = "The tools attached to this request come from the `network` server;"
        assert _violations(prompt, [_Tool("x", "analysis")], statement_expected=False)

    def test_a_workflow_for_a_sandbox_server_that_is_not_attached(self) -> None:
        from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider

        prompt = CAPE2SandboxProvider.CAPE_PROMPT_FRAGMENT
        assert _violations(prompt, [_Tool("sandbox_processes")], statement_expected=False)


def _turns(agent: Any, method: str, *args: Any) -> dict[str, str]:
    """Run one analyst entry point and return the system and human turns it sent."""
    from unittest.mock import patch

    sent: dict[str, str] = {}

    def _capture(messages: Any, *_a: Any, **_kw: Any) -> str:
        for role, text in messages:
            sent.setdefault(role, text)
        return "CLAIM: none\nEVIDENCE: none\nCONFIDENCE: 0.1\nTECHNIQUE: NONE\n"

    with (
        patch.object(agent, "_try_initialize_mcp", side_effect=lambda: bool(agent.tools)),
        patch.object(agent, "execute_tool_loop", side_effect=_capture),
        patch.object(agent, "_validate_isr", side_effect=lambda isr, _evidence: isr),
    ):
        getattr(agent, method)(*args)
    return sent


def _static_agent(tools: list[Any]) -> Any:
    agent = _container("none", "mock", "default").get_agent("static")
    agent.tools = tools
    for hint in (
        "_compute_sink_priority_hint",
        "_compute_function_hash_hint",
        "_compute_family_rag_hint",
    ):
        setattr(agent, hint, lambda *_a, **_k: "")
    return agent


_CHUNK = '{"sha256": "ab", "analysis_file_path": "/samples/ab.bin"}'


class TestTheHumanTurnSaysWhatTheListHolds:
    def test_the_static_turn_promises_no_decompiler_it_does_not_have(self) -> None:
        agent = _static_agent([_Tool("identify_file", "analysis"), _Tool("x", "knowledge")])
        turns = _turns(agent, "analyze_isr", _CHUNK)

        assert "decompile, xrefs" not in turns["human"]
        assert "load_program" not in turns["human"]
        assert "use exactly this string wherever a tool asks for a file" in turns["human"]
        assert "the `analysis` server" in turns["system"]
        assert NO_TOOLS_STATEMENT not in turns["system"]

    def test_the_static_turn_names_the_decompiler_it_has(self) -> None:
        agent = _static_agent([_Tool("load_program"), _Tool("decompile_function")])
        turns = _turns(agent, "analyze_isr", _CHUNK)

        assert "decompile, xrefs" in turns["human"]
        assert "LOAD THIS BINARY FIRST" in turns["human"]

    def test_a_static_turn_with_no_tools_says_nothing_about_them(self) -> None:
        agent = _static_agent([])
        turns = _turns(agent, "analyze_isr", _CHUNK)

        assert "You may use" not in turns["human"]
        assert "Sample path: /samples/ab.bin" in turns["human"]
        assert NO_TOOLS_STATEMENT in turns["system"]

    def test_a_dynamic_turn_with_no_tools_does_not_offer_them(self) -> None:
        agent = _container("none", "mock", "measurement").get_agent("dynamic")
        agent.tools = []
        turns = _turns(agent, "analyze_isr", '{"processes": []}')

        assert "You may use tools" not in turns["human"]
        assert NO_TOOLS_STATEMENT in turns["system"]
        assert "get_cuckoo_status" not in turns["system"]

    def test_a_pcap_turn_names_only_the_packet_tools_it_has(self) -> None:
        agent = _container("none", "mock", "default").get_agent("network")
        agent.tools = [_Tool("x", "knowledge")]
        turns = _turns(agent, "analyze_isr", "flows here, capture at /tmp/run/dump.pcap")

        assert "read_pcap_summary" not in turns["human"]
        assert "No packet tool is in your tool list" in turns["human"]

        agent.tools = [_Tool("read_pcap_summary", "network"), _Tool("x", "knowledge")]
        turns = _turns(agent, "analyze_isr", "flows here, capture at /tmp/run/dump.pcap")
        assert "(read_pcap_summary)" in turns["human"]


@pytest.mark.parametrize("role", ["static", "dynamic", "network"])
def test_a_revision_is_told_it_carries_no_tools(role: str) -> None:
    """A revision is one tools-free call, whatever the analyst's loop had."""
    from unittest.mock import patch

    agent = _container("none", "mock", "default").get_agent(role)
    agent.tools = [_Tool("x", "knowledge")]
    seen: list[str] = []

    def _ask(messages: Any, **_kw: Any) -> str:
        seen.extend(str(getattr(m, "content", "")) for m in messages if m.type == "system")
        return "CLAIM: none\nEVIDENCE: none\nCONFIDENCE: 0.1\nTECHNIQUE: NONE\nDISPUTES: NONE"

    with patch.object(agent, "ask_the_model", side_effect=_ask):
        agent.revise_isr("data", "own", {"peer": "report"}, "feedback")

    assert seen
    assert NO_TOOLS_STATEMENT in seen[0]
    assert "the `knowledge` server" not in seen[0]


def test_the_validation_turn_is_told_it_carries_no_tools(monkeypatch: Any) -> None:
    """The retry after a cut answer is tools-free, and its prompt says so."""
    from langchain_core.messages import AIMessage

    from maljan.agents import base_agent
    from maljan.pipeline.validation import Violation
    from maljan.schemas.isr_models import AgentISR, ClaimEvidence

    told = [Violation(code="isr.ungrounded_technique", message="cite ev_0001")]
    answers = iter([told, told, []])
    monkeypatch.setattr(base_agent, "validate_isr", lambda *_a, **_k: next(answers, []))
    agent = _static_agent([_Tool("x", "knowledge")])
    sent: list[list[Any]] = []

    def _capture(turns: list[Any], timeout: float) -> AIMessage:
        sent.append(list(turns))
        return AIMessage(content="CLAIM: c\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.5\nTECHNIQUE: T1055")

    agent._invoke_llm_with_timeout = _capture  # type: ignore[method-assign]
    isr = AgentISR(
        agent_id="static",
        domain="static",
        claims=[ClaimEvidence(claim="c", evidence_ref="x", confidence=0.5, technique_id="T1055")],
    )
    agent._validate_isr(isr, "the raw data")

    assert sent, "the validation turn was not sent"
    system = str(sent[0][0].content)
    assert NO_TOOLS_STATEMENT in system
    assert "the `knowledge` server" not in system


@pytest.mark.parametrize("key", ["static", "dynamic", "network", "reverser", "lead"])
def test_what_a_clone_copies_carries_no_sentence_about_the_source_tools(key: str) -> None:
    """A clone is seeded with the authored text; it gets its own sentence when resolved."""
    container = _container("ghidra", "mock", "default")
    resolved = asyncio.run(aresolve_agent(key, container))

    assert resolved.authored_prompt
    assert "The tools attached to this request" not in resolved.authored_prompt
    assert NO_TOOLS_STATEMENT not in resolved.authored_prompt
    assert "The tools attached to this request" in resolved.prompt
