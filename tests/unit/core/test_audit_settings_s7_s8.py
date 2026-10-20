"""Audit AUD-20: a save refuses an unknown capability and per-agent keys that name no agent.

What is already stored is never refused, so stored settings stay readable and
build as they always did.
"""

from __future__ import annotations

import pytest

from maljan.core.settings_overrides import build_settings, unknown_reference_refusals

ENTRY = {"provider": "openai", "model": "m"}


def _definition(capability: str) -> dict:
    return {
        "role": "generic",
        "prompt": "p",
        "tools": [{"kind": "capability", "capability": capability}],
    }


def test_s7_an_unknown_capability_is_refused_and_named() -> None:
    merged = {"agents.definitions": {"mine": _definition("nosuchkind")}}
    refused = unknown_reference_refusals(merged, {})
    assert list(refused) == ["core.agents.definitions"]
    assert "'mine'" in refused["core.agents.definitions"]
    assert "nosuchkind" in refused["core.agents.definitions"]


def test_s7_a_declared_capability_is_accepted() -> None:
    assert (
        unknown_reference_refusals({"agents.definitions": {"m": _definition("reputation")}}, {})
        == {}
    )


def test_s7_a_stored_unknown_capability_stays_readable_and_blocks_no_save() -> None:
    stored = {"agents.definitions": {"mine": _definition("nosuchkind")}}
    assert unknown_reference_refusals(stored, stored) == {}
    assert "mine" in build_settings(stored).agents.definitions


def test_s8_an_llm_agents_key_naming_no_agent_is_refused_with_the_roster() -> None:
    refused = unknown_reference_refusals({"llm.agents": {"ghost": ENTRY}}, {})
    message = refused["core.llm.agents"]
    assert "ghost" in message and "static" in message and "mediator" in message


def test_s8_the_roster_and_the_two_role_entries_are_accepted() -> None:
    merged = {"llm.agents": {"static": ENTRY, "mediator": ENTRY, "summarizer": ENTRY}}
    assert unknown_reference_refusals(merged, {}) == {}


def test_s8_a_stored_orphan_key_stays_readable_and_blocks_no_save() -> None:
    stored = {"llm.agents": {"ghost": ENTRY}}
    assert unknown_reference_refusals(stored, stored) == {}
    assert "ghost" in build_settings(stored).llm.agents


def test_s8_a_new_orphan_beside_a_stored_one_is_refused_alone() -> None:
    stored = {"llm.agents": {"ghost": ENTRY}}
    refused = unknown_reference_refusals({"llm.agents": {"ghost": ENTRY, "other": ENTRY}}, stored)
    assert "other" in refused["core.llm.agents"] and "ghost" not in refused["core.llm.agents"]


@pytest.mark.parametrize(
    "field", ["react_agent_timeout_overrides", "react_agent_max_steps_overrides"]
)
def test_s8_a_budget_override_keyed_by_no_agent_is_refused(field: str) -> None:
    refused = unknown_reference_refusals({field: {"ghost": 5}}, {})
    assert "ghost" in refused[f"core.{field}"]
