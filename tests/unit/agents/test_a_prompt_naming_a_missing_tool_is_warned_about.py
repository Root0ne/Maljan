"""An operator-written prompt that names a tool its agent lacks is said so, and runs anyway."""

from __future__ import annotations

import logging

from maljan.agents.composition import resolve_agent
from maljan.agents.prompt_tools import known_tool_names, names_in, warnings_for_settings
from maljan.core.config import Settings
from tests.unit.agents.test_composition import _Container

# A name the shipped declarations give a built-in server's tool; any other
# declared name would do, nothing here depends on which.
DECLARED = "yara_scan"


def _settings(prompt: str | None) -> Settings:
    definition: dict = {"role": "generic"}
    if prompt is not None:
        definition["prompt"] = prompt
    return Settings(
        _env_file=None,
        agents={
            "definitions": {"mine": definition},
            "profiles": {"one": {"analysts": ["mine"]}},
            "profile": "one",
        },
    )


def test_a_declared_name_absent_from_the_agents_set_is_a_warning(caplog):
    cfg = _settings(f"First run {DECLARED}, then summarise.")
    assert DECLARED in known_tool_names(cfg)
    with caplog.at_level(logging.WARNING):
        resolved = resolve_agent("mine", _Container(cfg))
    assert sum(DECLARED in r.getMessage() and "mine" in r.getMessage() for r in caplog.records) == 1
    assert not resolved.degradation_reasons  # an advisory is not a degradation
    assert "mine" in warnings_for_settings(cfg)


def test_an_ordinary_word_matching_no_tool_gives_none(caplog):
    cfg = _settings("Read the strings carefully and analyze what you find.")
    with caplog.at_level(logging.WARNING):
        resolved = resolve_agent("mine", _Container(cfg))
    assert not [r for r in caplog.records if "does not have" in r.getMessage()]
    assert not resolved.degradation_reasons
    assert warnings_for_settings(cfg) == {}


def test_a_name_inside_a_longer_word_does_not_count():
    known = frozenset({DECLARED})
    assert names_in(f"not_{DECLARED}_either and x{DECLARED}", known) == []
    assert names_in(f"Use `{DECLARED}`.", known) == [DECLARED]


def test_a_built_in_agent_gives_none(caplog):
    cfg = Settings(_env_file=None)
    with caplog.at_level(logging.WARNING):
        for key in ("static", "dynamic", "network"):
            resolve_agent(key, _Container(cfg))
    assert not [r for r in caplog.records if "does not have" in r.getMessage()]
    assert warnings_for_settings(cfg) == {}


def test_a_plain_word_is_prose_but_the_same_word_in_backticks_is_a_name(caplog):
    plain = _settings("Read the strings and analyze them.")
    assert "strings" in known_tool_names(plain)
    assert warnings_for_settings(plain) == {}
    quoted = _settings("Run `strings` on the sample.")
    with caplog.at_level(logging.WARNING):
        resolve_agent("mine", _Container(quoted))
    assert any("strings" in r.getMessage() and "mine" in r.getMessage() for r in caplog.records)
    assert "strings" in warnings_for_settings(quoted)["mine"]


def test_a_run_with_this_warning_is_not_marked_degraded():
    resolved = resolve_agent("mine", _Container(_settings(f"Use {DECLARED}.")))
    assert resolved.degradation_reasons == ()


def test_the_warning_never_blocks_a_run():
    resolved = resolve_agent("mine", _Container(_settings(f"Use {DECLARED}.")))
    assert resolved.key == "mine"
    assert resolved.prompt.startswith(f"Use {DECLARED}.")
