"""What a stage hands its agents: upstream findings, tools and data sources.

Three levers a team has over its members, and each of them is a promise to an
operator who cannot read the code. ``inject_upstream`` says what a later stage
is told about an earlier one. ``builtin_tools`` says whether a stage's agents
keep the four sidecars. ``data_sources`` says which slice of the job an agent
reads. The default team uses none of the first two and sets none of the third,
which is why the goldens did not move.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from maljan.agents.composition import mcp_refs_for
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.loaders.binary_chunker import TextChunk
from maljan.pipeline.nodes import make_stage_agent_node, upstream_findings
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


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


def _isr(agent: str, *claims: str) -> AgentISR:
    return AgentISR(
        agent_id=agent,
        domain="static",
        claims=[
            ClaimEvidence(
                claim=claim,
                evidence_ref=f"ev_{index:04d}",
                confidence=0.8,
                technique_id="T1055",
            )
            for index, claim in enumerate(claims, start=1)
        ],
        dissent_items=[],
    )


TEAM = [
    {"key": "triage", "kind": "analysis", "agents": ["static"]},
    {
        "key": "deep",
        "kind": "analysis",
        "agents": ["reverser"],
        "depends_on": ["triage"],
        "inject_upstream": "findings",
    },
    {"key": "verdict", "kind": "verdict", "agents": ["judge"], "depends_on": ["deep"]},
]


def _settings(stages: list[dict] | None = None, **over: Any) -> Settings:
    definitions = {"reverser": {"role": "generic", "prompt": "reverse it"}}
    definitions.update(over.pop("definitions", {}))
    return Settings(
        _env_file=None,
        agents={
            "definitions": definitions,
            "profiles": {"team": {"label": "Team", "stages": stages or TEAM}},
            "profile": "team",
        },
        **over,
    )


def _container(stages: list[dict] | None = None, **over: Any) -> ServiceContainer:
    return ServiceContainer(_settings(stages, **over), mock=True)


class TestUpstreamFindings:
    def _state(self) -> dict[str, Any]:
        return {
            "file_hash": "abc",
            "isr_reports": {"static": _isr("static", "packed with UPX", "writes to Run key")},
            "reports": {"static": "The full static prose report."},
        }

    def test_findings_carry_the_claim_spine_and_not_the_prose(self) -> None:
        container = _container()
        stage = container.active_profile().stage("deep")
        block = upstream_findings(stage, self._state(), container)  # type: ignore[arg-type]
        assert block.startswith("## Upstream findings")
        assert "### static" in block
        assert "packed with UPX [T1055, confidence 0.80, ev_0001]" in block
        assert "The full static prose report." not in block

    def test_full_adds_the_prose(self) -> None:
        container = _container()
        stage = (
            container.active_profile().stage("deep").model_copy(update={"inject_upstream": "full"})
        )
        block = upstream_findings(stage, self._state(), container)  # type: ignore[arg-type]
        assert "The full static prose report." in block

    def test_none_injects_nothing(self) -> None:
        container = _container()
        stage = (
            container.active_profile().stage("deep").model_copy(update={"inject_upstream": "none"})
        )
        assert upstream_findings(stage, self._state(), container) == ""  # type: ignore[arg-type]

    def test_a_stage_with_no_dependency_has_no_upstream(self) -> None:
        container = _container()
        stage = container.active_profile().stage("triage")
        assert upstream_findings(stage, self._state(), container) == ""  # type: ignore[arg-type]

    def test_the_block_is_cut_at_the_configured_budget_and_says_so(self) -> None:
        container = _container(reporting={"upstream_findings_max_chars": 120})
        stage = container.active_profile().stage("deep")
        state = {
            "file_hash": "abc",
            "isr_reports": {"static": _isr("static", *[f"claim number {i}" for i in range(50)])},
            "reports": {},
        }
        block = upstream_findings(stage, state, container)  # type: ignore[arg-type]
        assert block.endswith("[upstream findings truncated]")
        assert len(block) < 200

    def test_the_block_reaches_the_agent_at_the_head_of_its_first_chunk(self) -> None:
        settings = _settings()
        container = MagicMock()
        container.is_mock = False
        container.event_sink = None
        container.config = settings
        container.active_profile.return_value = settings.agents.profiles["team"]
        container.agent_role.return_value = "generic"
        agent = MagicMock()
        agent._resolved.static_provider_id = "none"
        agent.safe_analyze_isr.return_value = _isr("reverser", "found the unpacker")
        container.get_agent.return_value = agent
        container.load_data_for_agent.return_value = [_chunk("the sample profile")]

        stage = settings.agents.profiles["team"].stage("deep")
        make_stage_agent_node(stage, "reverser", container)(self._state())  # type: ignore[arg-type]

        shown = agent.safe_analyze_isr.call_args[0][0]
        assert shown.startswith("## Upstream findings")
        assert shown.endswith("the sample profile")


class TestBuiltinToolsOnAStage:
    def test_a_stage_that_keeps_them_leaves_a_definition_s_references_alone(self) -> None:
        settings = _settings(
            [
                {"key": "triage", "kind": "analysis", "agents": ["static"]},
                {
                    "key": "verdict",
                    "kind": "verdict",
                    "agents": ["judge"],
                    "depends_on": ["triage"],
                },
            ]
        )
        assert [r.server for r in mcp_refs_for(settings, "static")] == ["analysis", "knowledge"]

    def test_a_stage_that_withholds_them_takes_the_four_sidecars_away(self) -> None:
        settings = _settings(
            [
                {"key": "triage", "kind": "analysis", "agents": ["static"], "builtin_tools": False},
                {
                    "key": "verdict",
                    "kind": "verdict",
                    "agents": ["judge"],
                    "depends_on": ["triage"],
                },
            ]
        )
        assert mcp_refs_for(settings, "static") == []

    def test_it_applies_to_that_stage_alone(self) -> None:
        settings = _settings(
            [
                {"key": "triage", "kind": "analysis", "agents": ["static"], "builtin_tools": False},
                {
                    "key": "deep",
                    "kind": "analysis",
                    "agents": ["network"],
                    "depends_on": ["triage"],
                },
                {"key": "verdict", "kind": "verdict", "agents": ["judge"], "depends_on": ["deep"]},
            ]
        )
        assert mcp_refs_for(settings, "static") == []
        assert [r.server for r in mcp_refs_for(settings, "network")] == ["network", "knowledge"]


REPORT = {
    "target": {"file": {"sha256": "abc123"}, "size": 2048},
    "behavior": {"processes": [{"name": "evil.exe"}]},
    "network": {
        "dns": [{"request": "c2.example"}],
        "http": [],
        "tcp": [],
        "hosts": [],
        "domains": [],
    },
    "marker": "whole-report",
}


class TestDataSources:
    def _container(self, sources: list[str]) -> ServiceContainer:
        return ServiceContainer(
            _settings(
                definitions={
                    "picky": {"role": "generic", "prompt": "look", "data_sources": sources}
                }
            ),
            mock=True,
        )

    def _text(self, sources: list[str], **over: Any) -> str:
        container = self._container(sources)
        chunks = container.load_data_for_agent(
            "picky", file_hash="abc123", sandbox_report=REPORT, **over
        )
        return "\n".join(c.content for c in chunks)

    def test_sample_path_carries_the_path_and_nothing_else(self) -> None:
        text = self._text(["sample.path"], sample_path="/srv/samples/abc123.exe")
        assert text == "analysis_file_path: /srv/samples/abc123.exe"

    def test_sample_path_with_no_path_contributes_nothing(self) -> None:
        assert self._text(["sample.path"]) == ""

    def test_sample_chunks_reads_the_parsed_sample(self) -> None:
        text = self._text(["sample.chunks"])
        assert "abc123" in text
        assert "whole-report" not in text

    def test_each_sandbox_slice_is_its_own_block(self) -> None:
        assert '"sha256": "abc123"' in self._text(["sandbox.target"])
        assert "whole-report" not in self._text(["sandbox.target"])
        assert "c2.example" in self._text(["sandbox.network"])
        # The behaviour slice is what the dynamic parser makes of the report,
        # not the raw JSON, so it is recognised by the summary it renders.
        assert "Sandbox Behavioral Summary" in self._text(["sandbox.behavior"])
        assert "whole-report" in self._text(["sandbox.full"])

    def test_a_sandbox_slice_with_no_report_contributes_nothing(self) -> None:
        container = self._container(["sandbox.network"])
        assert container.load_data_for_agent("picky", file_hash="abc123") == []

    def test_the_sources_are_concatenated_in_the_order_they_are_listed(self) -> None:
        text = self._text(["sample.path", "sandbox.network"], sample_path="/srv/samples/abc123.exe")
        assert text.index("analysis_file_path") < text.index("c2.example")

    def test_an_empty_list_falls_back_to_the_role_s_historical_slice(self) -> None:
        container = ServiceContainer(_settings(), mock=True)
        network = container.load_data_for_agent(
            "network", file_hash="abc123", sandbox_report=REPORT
        )
        assert "c2.example" in "\n".join(c.content for c in network)
        assert "whole-report" not in "\n".join(c.content for c in network)

    def test_an_unknown_source_is_a_settings_error(self) -> None:
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError, match="unknown data source 'sandbox.magic'"):
            _settings(
                definitions={
                    "picky": {
                        "role": "generic",
                        "prompt": "look",
                        "data_sources": ["sandbox.magic"],
                    }
                }
            )


class TestTheReporterIsADefinitionLikeAnyOther:
    def test_it_is_seeded_with_the_report_role_and_no_tools(self) -> None:
        definition = Settings(_env_file=None).agents.definitions["reporter"]
        assert definition.role == "report"
        assert definition.tools == []

    def test_the_report_stage_runs_on_the_judge_model_until_it_is_given_one(self) -> None:
        """The behaviour the report has always had, now reachable as a setting.

        ``llm.agents.reporter`` decides the model when it is set; with nothing
        set the reporter falls back to the *judge* role rather than the expert
        one, which is the model the narrative and composer rounds were built
        with before the reporter was a definition.
        """
        from maljan.llm.registry import LLMProviderRegistry

        registry = LLMProviderRegistry(Settings(_env_file=None))
        roles: list[str] = []
        registry.build_model = lambda role, **_: roles.append(role)  # type: ignore[assignment]
        registry.build_model_for_agent("reporter", fallback_role="judge")
        assert roles == ["judge"]

    def test_a_configured_reporter_model_is_the_one_it_uses(self) -> None:
        settings = Settings(
            _env_file=None,
            llm={"agents": {"reporter": {"provider": "ollama", "model": "qwen3:8b"}}},
        )
        assert settings.llm.agents["reporter"].model == "qwen3:8b"


class TestASandboxReferenceIsNotOnlyForTheDynamicRole:
    def test_a_generic_agent_in_any_stage_gets_the_in_process_sandbox_tools(self) -> None:
        """``ToolRef(kind="sandbox")`` is a definition's choice, not a role's.

        The dynamic analyst is only the obvious holder of one. A generic agent
        in a stage of its own asks for the same thing and must get the same
        closures over the job's report.
        """
        from maljan.agents.composition import _sandbox_tools

        settings = _settings(
            [
                {"key": "triage", "kind": "analysis", "agents": ["static"]},
                {
                    "key": "detonate",
                    "kind": "analysis",
                    "agents": ["watcher"],
                    "depends_on": ["triage"],
                },
                {
                    "key": "verdict",
                    "kind": "verdict",
                    "agents": ["judge"],
                    "depends_on": ["detonate"],
                },
            ],
            definitions={
                "watcher": {
                    "role": "generic",
                    "prompt": "watch it run",
                    "tools": [{"kind": "sandbox"}],
                }
            },
        )
        container = ServiceContainer(settings, mock=True)
        container.sandbox_report = REPORT
        names = [t.name for t in _sandbox_tools(container, settings.agents.definitions["watcher"])]
        assert "sandbox_processes" in names
        assert "sandbox_network" in names

    def test_the_team_s_sandbox_exclusion_still_withholds_them(self) -> None:
        from maljan.agents.composition import _sandbox_tools

        settings = _settings(
            [
                {"key": "detonate", "kind": "analysis", "agents": ["watcher"]},
                {
                    "key": "verdict",
                    "kind": "verdict",
                    "agents": ["judge"],
                    "depends_on": ["detonate"],
                },
            ],
            definitions={
                "watcher": {
                    "role": "generic",
                    "prompt": "watch it run",
                    "tools": [{"kind": "sandbox"}],
                }
            },
        )
        settings.agents.profiles["team"].exclude_sandbox_tools = True
        container = ServiceContainer(settings, mock=True)
        container.sandbox_report = REPORT
        assert _sandbox_tools(container, settings.agents.definitions["watcher"]) == []
