"""What a stored definition means when it leaves something out, or kept an old seed.

Two rules, both about reading the definition map a database holds.

A seeded definition is stored whole on every save, so a database holds each
seed's prompt as it was on the day of its last save. A release that rewrites
a seeded prompt must not turn that row into "an operator's own agent on a
reserved name" and rename it out of the way: a prompt the seed itself once
shipped is the seed's.

An operator's definition that has no tool list takes its role seed's list,
and one that has a list, empty included, keeps it: a clone of ``static`` on
r2 written as two fields keeps the analysis sidecar the static seed reads.
"""

from __future__ import annotations

import hashlib

import pytest

from app.services.agent_map import validate_definitions
from maljan.agents import prompts
from maljan.core.config import (
    FORMER_SEED_PROMPT_DIGESTS,
    Settings,
    as_stored_builtin,
    with_the_role_seed_tools,
)


def _servers(definition) -> list[str | None]:
    return [ref.server for ref in definition.tools]


class TestAFormerSeedPromptIsTheSeed:
    def _stored_reverser(self, prompt: str) -> dict:
        row = Settings(_env_file=None).agents.definitions["reverser"].model_dump(mode="json")
        row["prompt"] = prompt
        return row

    def test_a_row_saved_under_an_older_seed_loads_as_the_seed(self, monkeypatch) -> None:
        old = "an older seeded prompt"
        digest = hashlib.sha256(old.encode()).hexdigest()
        monkeypatch.setitem(
            FORMER_SEED_PROMPT_DIGESTS,
            "reverser",
            FORMER_SEED_PROMPT_DIGESTS["reverser"] | {digest},
        )

        cfg = Settings(
            _env_file=None, agents={"definitions": {"reverser": self._stored_reverser(old)}}
        )

        assert "reverser_custom" not in cfg.agents.definitions
        assert cfg.agents.definitions["reverser"].prompt == prompts.REVERSER_PROMPT

    def test_the_settings_api_takes_it_as_the_seed_too(self, monkeypatch) -> None:
        old = "an older seeded prompt"
        monkeypatch.setitem(
            FORMER_SEED_PROMPT_DIGESTS,
            "reverser",
            FORMER_SEED_PROMPT_DIGESTS["reverser"] | {hashlib.sha256(old.encode()).hexdigest()},
        )
        stored = validate_definitions(
            {"reverser": self._stored_reverser(old)},
            servers={"analysis": None, "knowledge": None, "virustotal": None},
        )
        assert stored["reverser"]["prompt"] == prompts.REVERSER_PROMPT

    def test_an_operator_s_own_prompt_is_still_moved_out_of_the_way(self) -> None:
        cfg = Settings(
            _env_file=None,
            agents={"definitions": {"reverser": self._stored_reverser("my own reverser")}},
        )
        assert cfg.agents.definitions["reverser_custom"].prompt == "my own reverser"

    @pytest.mark.parametrize(
        ("key", "prompt"),
        [
            ("reverser", prompts.REVERSER_PROMPT),
            ("triage", prompts.TRIAGE_PROMPT),
            ("android_static", prompts.ANDROID_STATIC_PROMPT),
            ("lead", prompts.LEAD_PROMPT),
        ],
    )
    def test_no_current_seed_prompt_is_listed_as_a_former_one(self, key: str, prompt: str) -> None:
        digest = hashlib.sha256(prompt.encode()).hexdigest()
        assert digest not in FORMER_SEED_PROMPT_DIGESTS.get(key, frozenset())

    @pytest.mark.parametrize(
        "digest",
        [
            # The reverser prompt before it asked for every branch of a dispatcher.
            "486bffd12746ef38cdd4bcdc94413e03584a5009abb2e4f5bfde6a6d6d3e2875",
            # The reverser prompt before it was handed resolved hashes and decoded strings.
            "f0add93b08ffd9897fdb84d80f16f8b956681e28c2c3fbce8276f2746c6388b7",
        ],
    )
    def test_every_reverser_prompt_a_release_shipped_is_listed(self, digest: str) -> None:
        assert digest in FORMER_SEED_PROMPT_DIGESTS["reverser"]

    def test_only_seeded_keys_are_listed(self) -> None:
        seeded = set(Settings(_env_file=None).agents.definitions)
        assert set(FORMER_SEED_PROMPT_DIGESTS) <= seeded

    def test_the_normaliser_leaves_every_other_field_alone(self) -> None:
        entry = {"role": "generic", "enabled": False, "tools": [], "prompt": "mine"}
        assert as_stored_builtin("reverser", entry) == {
            "role": "generic",
            "enabled": False,
            "prompt": "mine",
        }


class TestAClonesMissingToolListIsItsRoleSeeds:
    def test_a_static_clone_on_r2_keeps_the_sidecars(self) -> None:
        cfg = Settings(
            _env_file=None,
            agents={"definitions": {"static_r2": {"role": "static", "static_provider": "r2"}}},
        )
        clone = cfg.agents.definitions["static_r2"]
        assert _servers(clone) == _servers(cfg.agents.definitions["static"])
        assert "analysis" in _servers(clone)

    def test_an_explicit_empty_list_means_none(self) -> None:
        cfg = Settings(
            _env_file=None,
            agents={"definitions": {"bare": {"role": "static", "tools": []}}},
        )
        assert cfg.agents.definitions["bare"].tools == []

    def test_an_explicit_list_is_the_operator_s(self) -> None:
        cfg = Settings(
            _env_file=None,
            agents={
                "definitions": {
                    "static_r2": {
                        "role": "static",
                        "static_provider": "r2",
                        "tools": [{"kind": "mcp", "server": "analysis"}],
                    }
                }
            },
        )
        assert _servers(cfg.agents.definitions["static_r2"]) == ["analysis"]

    def test_a_generic_agent_has_no_role_seed_to_inherit(self) -> None:
        cfg = Settings(
            _env_file=None,
            agents={"definitions": {"mine": {"role": "generic", "prompt": "p"}}},
        )
        assert cfg.agents.definitions["mine"].tools == []

    @pytest.mark.parametrize("role", ["dynamic", "network"])
    def test_every_analyst_role_inherits_the_same_way(self, role: str) -> None:
        cfg = Settings(
            _env_file=None,
            agents={"definitions": {f"{role}_2": {"role": role}}},
        )
        assert _servers(cfg.agents.definitions[f"{role}_2"]) == _servers(
            cfg.agents.definitions[role]
        )

    def test_the_settings_api_stores_the_inherited_list(self) -> None:
        """Stored as a list, so the rule is applied once and what the console
        shows is what the run reads."""
        stored = validate_definitions(
            {"static_r2": {"role": "static", "static_provider": "r2"}},
            servers={"analysis": None, "knowledge": None, "virustotal": None},
        )
        assert [ref["server"] for ref in stored["static_r2"]["tools"]] == [
            "analysis",
            "knowledge",
            "virustotal",
        ]

    def test_the_helper_only_fills_a_missing_list(self) -> None:
        assert with_the_role_seed_tools({"role": "static", "tools": []})["tools"] == []
        assert with_the_role_seed_tools({"role": "generic"}) == {"role": "generic"}


def test_the_team_preview_reads_a_staged_clone_as_the_save_will() -> None:
    from app.services.agent_map import staged_definitions

    staged = staged_definitions({"static_r2": {"role": "static", "static_provider": "r2"}})
    assert [ref["server"] for ref in staged["static_r2"]["tools"]] == [
        "analysis",
        "knowledge",
        "virustotal",
    ]
    assert staged_definitions({"bare": {"role": "static", "tools": []}})["bare"]["tools"] == []
