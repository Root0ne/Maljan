"""Whether an analyst holds any of the data it declares it reads, decided from declarations.

``pipeline.data_needs`` reads an analyst's input slice (its ``data_sources``,
else its role's) and its tools' declared sources against the kinds of data
the job holds. These tests pin each kind, mixed tool lists, tools and servers
that declare nothing, and the one rule that keeps an undeclared analyst at
full strength: anything not tied to a kind of job data keeps it running.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from malspark.core.config import AgentDefinition, ToolRef
from malspark.pipeline.data_needs import (
    CAPTURE,
    NETWORK,
    SAMPLE,
    SANDBOX_REPORT,
    SANDBOX_TARGET,
    STORED,
    Reads,
    agent_reads,
    dataless_reason,
    job_data,
    missing_kinds,
)

# Declared roles of the servers these tests bind, as a block declares them.
_ROLES: dict[str, tuple[str, ...]] = {
    "pcaps": ("capture",),
    "catalogue": ("reference",),
    "lookup": ("reputation",),
    "mixed": ("capture", "decoder"),
    "bare": (),
}


# The servers a capability resolves to, as ``composition.capability_servers`` reads them.
_CAPABILITIES: dict[str, tuple[str, ...]] = {"reputation": ("lookup",), "capture": ("pcaps",)}


def _roles(server: str) -> Sequence[str] | None:
    return _ROLES.get(server)


def _servers(definition: AgentDefinition | None, also: Sequence[str] = ()) -> set[str]:
    """The servers the definition reaches: its references, its capabilities' servers, ``also``."""
    out = set(also)
    for ref in definition.tools if definition is not None else []:
        if ref.kind == "mcp" and ref.server:
            out.add(ref.server)
        elif ref.kind == "capability" and ref.capability:
            out.update(_CAPABILITIES.get(ref.capability, ()))
    return out


def _reads(
    definition: AgentDefinition | None, *, sandbox: bool = False, also: Sequence[str] = ()
) -> Reads:
    role = str(definition.role) if definition is not None else ""
    return agent_reads(
        definition,
        role,
        sample_fed=role in ("static", "generic", "lead"),
        sandbox_report=sandbox,
        servers=_servers(definition, also),
        server_roles=_roles,
    )


def _missing(definition: AgentDefinition | None, job: object, name: str = "a") -> object:
    sandbox = bool(getattr(job, "sandbox_report", False))
    return missing_kinds(_reads(definition, sandbox=sandbox), job, name)  # type: ignore[arg-type]


_NO_STORED = job_data(None, (), stored=lambda _agent: False)
_REPORT = {"target": {"sha256": "abc"}, "behavior": {"processes": [{"pid": 1}]}}
_REPORT_WITH_NETWORK = {**_REPORT, "network": {"dns": [{"request": "example.org"}]}}


class TestTheJobsData:
    def test_the_sample_is_always_held(self) -> None:
        assert SAMPLE in job_data(None).held

    def test_a_report_holds_the_report_and_its_target(self) -> None:
        job = job_data(_REPORT)
        assert {SANDBOX_REPORT, SANDBOX_TARGET} <= job.held
        assert NETWORK not in job.held

    def test_an_empty_network_block_is_no_network_data(self) -> None:
        job = job_data({**_REPORT, "network": {"dns": [], "http": [], "tcp": []}})
        assert NETWORK not in job.held

    def test_a_filled_network_row_of_any_kind_is_network_data(self) -> None:
        assert NETWORK in job_data(_REPORT_WITH_NETWORK).held
        assert NETWORK in job_data({**_REPORT, "network": {"smtp": [{"to": "x"}]}}).held

    def test_a_capture_is_network_data_without_a_report(self) -> None:
        job = job_data(None, ("/jobs/1/captures/dump.pcap",))
        assert {CAPTURE, NETWORK} <= job.held
        assert SANDBOX_REPORT not in job.held

    def test_stored_data_is_asked_per_agent(self) -> None:
        job = job_data(None, (), stored=lambda agent: agent == "has")
        assert job.holds(STORED, "has")
        assert not job.holds(STORED, "lacks")


class TestEachDataKind:
    def test_a_role_given_the_sample_always_holds_data(self) -> None:
        static = AgentDefinition(role="static", tools=[])
        assert _missing(static, _NO_STORED) is None
        generic = AgentDefinition(
            role="generic", prompt="p", tools=[], data_sources=["sandbox.full"]
        )
        assert _missing(generic, _NO_STORED) is None

    def test_a_sandbox_role_with_no_report_and_no_stored_data_lacks_it(self) -> None:
        dynamic = AgentDefinition(role="dynamic", tools=[ToolRef(kind="sandbox")])
        assert _missing(dynamic, _NO_STORED) == frozenset({STORED, SANDBOX_REPORT})

    def test_stored_data_for_the_sample_is_data(self) -> None:
        dynamic = AgentDefinition(role="dynamic", tools=[ToolRef(kind="sandbox")])
        job = job_data(None, (), stored=lambda _agent: True)
        assert _missing(dynamic, job) is None

    def test_a_report_is_data_for_a_sandbox_role(self) -> None:
        dynamic = AgentDefinition(role="dynamic", tools=[ToolRef(kind="sandbox")])
        assert _missing(dynamic, job_data(_REPORT)) is None

    def test_a_network_role_lacks_data_on_a_report_with_no_network_block(self) -> None:
        network = AgentDefinition(role="network", tools=[ToolRef(kind="mcp", server="pcaps")])
        assert _missing(network, job_data(_REPORT)) == frozenset({NETWORK, CAPTURE})

    def test_a_network_role_holds_data_where_the_report_has_rows(self) -> None:
        network = AgentDefinition(role="network", tools=[ToolRef(kind="mcp", server="pcaps")])
        assert _missing(network, job_data(_REPORT_WITH_NETWORK)) is None

    def test_a_capture_tool_holds_data_where_the_job_has_a_capture(self) -> None:
        network = AgentDefinition(role="network", tools=[ToolRef(kind="mcp", server="pcaps")])
        job = job_data(None, ("/c/dump.pcap",), stored=lambda _agent: False)
        assert _missing(network, job) is None

    @pytest.mark.parametrize(
        ("source", "kind"),
        [
            ("sandbox.target", SANDBOX_TARGET),
            ("sandbox.behavior", SANDBOX_REPORT),
            ("sandbox.network", NETWORK),
            ("sandbox.full", SANDBOX_REPORT),
            ("sample.chunks", STORED),
        ],
    )
    def test_each_named_source_reads_its_kind(self, source: str, kind: str) -> None:
        agent = AgentDefinition(role="dynamic", tools=[], data_sources=[source])
        assert _missing(agent, _NO_STORED) == frozenset({kind})

    def test_the_sample_path_source_is_always_held(self) -> None:
        agent = AgentDefinition(role="dynamic", tools=[], data_sources=["sample.path"])
        assert _missing(agent, _NO_STORED) is None


class TestMixedAndUndeclaredTools:
    def test_a_reference_tool_reads_no_job_data_and_keeps_nothing_running(self) -> None:
        dynamic = AgentDefinition(
            role="dynamic",
            tools=[ToolRef(kind="sandbox"), ToolRef(kind="mcp", server="catalogue")],
        )
        assert _missing(dynamic, _NO_STORED) == frozenset({STORED, SANDBOX_REPORT})

    def test_a_tool_over_the_sample_keeps_the_analyst_running(self) -> None:
        network = AgentDefinition(
            role="network",
            tools=[
                ToolRef(kind="mcp", server="pcaps"),
                ToolRef(kind="capability", capability="reputation"),
            ],
        )
        assert _missing(network, job_data(_REPORT)) is None

    def test_a_server_that_declares_no_role_keeps_the_analyst_running(self) -> None:
        agent = AgentDefinition(role="dynamic", tools=[ToolRef(kind="mcp", server="bare")])
        assert _missing(agent, _NO_STORED) is None

    def test_a_server_whose_declaration_cannot_be_read_keeps_the_analyst_running(self) -> None:
        agent = AgentDefinition(role="dynamic", tools=[ToolRef(kind="mcp", server="unknown")])
        assert _missing(agent, _NO_STORED) is None

    def test_a_server_with_one_untied_role_keeps_the_analyst_running(self) -> None:
        agent = AgentDefinition(role="network", tools=[ToolRef(kind="mcp", server="mixed")])
        assert _missing(agent, job_data(_REPORT)) is None

    def test_a_provider_or_an_ask_keeps_the_analyst_running(self) -> None:
        for ref in (ToolRef(kind="provider"), ToolRef(kind="agent", agent="static")):
            agent = AgentDefinition(role="dynamic", tools=[ToolRef(kind="sandbox"), ref])
            assert _missing(agent, _NO_STORED) is None

    def test_a_capability_tied_to_a_kind_reads_that_kind(self) -> None:
        agent = AgentDefinition(
            role="network", tools=[ToolRef(kind="capability", capability="capture")]
        )
        assert _missing(agent, job_data(_REPORT)) == frozenset({NETWORK, CAPTURE})

    def test_an_analyst_with_no_definition_is_never_skipped(self) -> None:
        assert _missing(None, _NO_STORED) is None

    def test_a_server_bound_by_its_own_agents_list_counts(self) -> None:
        """Bound by ``mcp.servers.<x>.agents`` rather than a reference: still the agent's."""
        network = AgentDefinition(role="network", tools=[ToolRef(kind="mcp", server="pcaps")])
        job = job_data(_REPORT)
        assert missing_kinds(_reads(network, sandbox=True, also=["lookup"]), job, "a") is None
        assert missing_kinds(_reads(network, sandbox=True), job, "a") == frozenset(
            {NETWORK, CAPTURE}
        )

    def test_servers_that_cannot_be_read_keep_the_analyst_running(self) -> None:
        dynamic = AgentDefinition(role="dynamic", tools=[ToolRef(kind="sandbox")])
        reads = agent_reads(
            dynamic,
            "dynamic",
            sample_fed=False,
            sandbox_report=False,
            servers=None,
            server_roles=_roles,
        )
        assert reads.untied


class TestTheReason:
    def test_it_names_every_kind_missing_once(self) -> None:
        reason = dataless_reason(
            {"a": frozenset({SANDBOX_REPORT, STORED}), "b": frozenset({SANDBOX_REPORT})}
        )
        assert reason == (
            f"the job holds none of the data its analysts read ({SANDBOX_REPORT}, {STORED})"
        )


class TestStoredDataIsAskedWithoutLoadingIt:
    def test_the_loader_holds_what_it_would_load(self, tmp_path: Path) -> None:
        from malspark.loaders.file_loader import FileDataLoader

        (tmp_path / "dynamic").mkdir()
        (tmp_path / "dynamic" / "abc123.json").write_text("{}", encoding="utf-8")
        loader = FileDataLoader(samples_dir=str(tmp_path))
        assert loader.holds("abc123", "dynamic")
        assert not loader.holds("abc123", "network")
        # An identifier the loader refuses is left for the load to refuse.
        assert loader.holds("../x", "dynamic")

    def test_the_container_reads_a_loaded_placeholder_as_no_data(self) -> None:
        import threading
        from types import SimpleNamespace

        from malspark.core.container import ServiceContainer
        from malspark.loaders.file_loader import no_data_placeholder

        held = SimpleNamespace(
            _lock=threading.RLock(),
            _data_cache={
                ("abc", "dynamic"): no_data_placeholder("abc", "dynamic"),
                ("abc", "network"): "DNS: example.org",
            },
            loader=SimpleNamespace(holds=lambda _s, _d: False),
        )
        holds = ServiceContainer.holds_stored_data
        assert not holds(held, "abc", "dynamic")  # type: ignore[arg-type]
        assert holds(held, "abc", "network")  # type: ignore[arg-type]
        assert not holds(held, "abc", "static")  # type: ignore[arg-type]
        held.loader = SimpleNamespace()
        assert holds(held, "abc", "static")  # type: ignore[arg-type]
