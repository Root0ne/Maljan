"""Every agent definition declares its category, separate from its role (T-559).

The role picks the code that runs an agent; the category says what the agent
does, and the platform offers an agent its own steps by it:

- the built-ins ship with theirs, read here off a real ``Settings()``;
- a definition that names none reads the category its role and tools fit,
  from the role, the kinds of its tool references and its input slices,
  never a name, and ``other`` where they tell nothing;
- a stored built-in reads its seed's category, and one that names another is
  an edit of a built-in, refused as any other;
- the run's roster carries it beside the role, a stored document that names
  none included.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from malspark.agents.composition import ResolvedAgent
from malspark.core.agent_category import (
    AGENT_CATEGORIES,
    declared_category,
    fitting_category,
)
from malspark.core.config import AgentDefinition, Settings, ToolRef
from malspark.pipeline.events import roster_payload


def _settings(**definitions: Any) -> Settings:
    return Settings(_env_file=None, agents={"definitions": definitions})


class TestTheBuiltIns:
    def test_each_ships_its_category(self) -> None:
        shipped = {
            key: d.category for key, d in Settings(_env_file=None).agents.definitions.items()
        }
        assert shipped == {
            "static": "code_reader",
            "dynamic": "dynamic",
            "network": "network",
            "judge": "other",
            "reporter": "other",
            "triage": "static",
            "android_static": "static",
            "reverser": "code_reader",
            "lead": "other",
        }

    def test_a_stored_built_in_that_names_none_reads_its_seed_s(self) -> None:
        cfg = _settings(triage={"role": "generic", "enabled": False})
        assert cfg.agents.definitions["triage"].category == "static"
        assert cfg.agents.definitions["triage"].enabled is False

    def test_a_stored_built_in_with_another_category_is_an_edit_of_a_built_in(self) -> None:
        with pytest.raises(ValidationError, match="'network' is built in; clone it to change it"):
            _settings(network={"role": "network", "category": "intel"})

    def test_every_value_is_one_the_model_takes(self) -> None:
        for category in AGENT_CATEGORIES:
            assert AgentDefinition(role="generic", prompt="p", category=category).category == (
                category
            )
        with pytest.raises(ValidationError):
            AgentDefinition(role="generic", prompt="p", category="reverser")


class TestADefinitionThatNamesNone:
    @pytest.mark.parametrize(
        ("definition", "category"),
        [
            ({"role": "static"}, "code_reader"),
            ({"role": "dynamic"}, "dynamic"),
            ({"role": "network"}, "network"),
            ({"role": "judge"}, "other"),
            ({"role": "report"}, "other"),
            ({"role": "generic", "tools": [{"kind": "provider"}]}, "code_reader"),
            ({"role": "lead", "tools": [{"kind": "provider", "provider": "x"}]}, "code_reader"),
            ({"role": "generic", "tools": [{"kind": "sandbox"}]}, "dynamic"),
            ({"role": "generic", "data_sources": ["sandbox.network"]}, "network"),
            ({"role": "generic", "data_sources": ["sandbox.behavior"]}, "dynamic"),
            (
                {"role": "generic", "data_sources": ["sandbox.network", "sample.chunks"]},
                "dynamic",
            ),
            (
                {
                    "role": "generic",
                    "tools": [
                        {"kind": "capability", "capability": "reputation"},
                        {"kind": "agent", "agent": "static"},
                    ],
                },
                "intel",
            ),
        ],
    )
    def test_reads_the_one_its_role_and_tools_fit(
        self, definition: dict[str, Any], category: str
    ) -> None:
        assert fitting_category(definition) == (category, True)
        assert AgentDefinition.model_validate({"prompt": "p", **definition}).category == category

    def test_one_nothing_tells_is_other_and_says_so(self) -> None:
        definition = {"role": "generic", "tools": [{"kind": "mcp", "server": "knowledge"}]}
        assert fitting_category(definition) == ("other", False)

    def test_no_name_is_read(self) -> None:
        """A server, a tool, a key and a label named for a decompiler tell nothing."""
        named = {
            "role": "generic",
            "label": "Ghidra reverser",
            "prompt": "decompile everything",
            "tools": [{"kind": "mcp", "server": "ghidra", "name": "decompile_function"}],
        }
        assert fitting_category(named) == ("other", False)
        cfg = _settings(ghidra_reverser={**named, "tools": []})
        assert cfg.agents.definitions["ghidra_reverser"].category == "other"

    def test_a_model_and_its_dump_fit_alike(self) -> None:
        model = AgentDefinition(role="generic", prompt="p", tools=[ToolRef(kind="sandbox")])
        dumped = model.model_dump(mode="json")
        del dumped["category"]
        assert fitting_category(model) == fitting_category(dumped) == ("dynamic", True)

    def test_a_category_it_names_is_kept(self) -> None:
        cfg = _settings(mine={"role": "generic", "prompt": "p", "category": "intel"})
        assert cfg.agents.definitions["mine"].category == "intel"
        assert cfg.agents.definitions["mine"].model_dump()["category"] == "intel"


class TestWhatReadsIt:
    def test_a_resolved_agent_without_a_definition_is_other(self) -> None:
        resolved = ResolvedAgent(
            key="k", role="generic", prompt="", tools=[], static_provider_id="none", llm=None
        )
        assert resolved.category == "other"

    def test_declared_reads_a_model_a_dict_and_nothing(self) -> None:
        assert declared_category(None) is None
        assert declared_category({"role": "generic"}) is None
        assert declared_category({"category": "not one"}) is None
        assert declared_category({"category": "network"}) == "network"
        assert declared_category(AgentDefinition(role="dynamic")) == "dynamic"

    def test_the_roster_carries_it_beside_the_role(self) -> None:
        cfg = Settings(_env_file=None)
        roster = roster_payload(cfg.agents.profiles["default"], cfg.agents.definitions)
        by_key = {a["key"]: a for a in roster["agents"]}
        assert by_key["static"]["category"] == "code_reader"
        assert by_key["judge"]["category"] == "other"

    def test_a_stored_document_that_names_none_reads_the_one_it_fits(self) -> None:
        profile = {"stages": [{"key": "analysis", "kind": "analysis", "agents": ["mine", "gone"]}]}
        definitions = {"mine": {"role": "generic", "tools": [{"kind": "sandbox"}]}}
        roster = roster_payload(profile, definitions)
        by_key = {a["key"]: a for a in roster["agents"]}
        assert by_key["mine"]["category"] == "dynamic"
        # A stage names an agent no definition describes: no category to state.
        assert by_key["gone"]["category"] == ""
