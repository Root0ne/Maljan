"""A setting the run's snapshot lacks is read as the replayed tree's own default.

The replay of a ref decides with that ref's rules over the stored run's
settings. A value the snapshot does not hold is the tree's default, read from
its own settings model, never a number the replay wrote down: a default the
platform changes then shows in ``--compare`` as the difference it makes.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest
from scripts.replay import rules
from scripts.replay.guard import replay_environment
from scripts.replay.stored import StoredRun


def _run(snapshot: dict[str, object]) -> rules._Run:
    stored = StoredRun(name="r", root=Path("."), run_summary={"settings_snapshot": snapshot})
    return rules._Run(stored=stored, show_text=False)


def test_a_validation_setting_follows_the_tree_s_default(monkeypatch: pytest.MonkeyPatch) -> None:
    from maljan.core import settings_overrides

    real = settings_overrides.build_settings

    def a_tree_whose_default_moved(overrides):  # type: ignore[no-untyped-def]
        return real({"validation.alignment_threshold": 0.3, **overrides})

    monkeypatch.setattr(settings_overrides, "build_settings", a_tree_whose_default_moved)
    with replay_environment({}):
        assert rules._setting("validation.alignment_threshold") == pytest.approx(0.3)
    with replay_environment({"validation.alignment_threshold": 0.07}):
        assert rules._setting("validation.alignment_threshold") == pytest.approx(0.07)


def test_the_analyst_checks_run_on_a_moved_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """A replay's answer checks are handed the tree's default, not a number of the replay's."""
    from types import SimpleNamespace

    from maljan.core import settings_overrides
    from maljan.pipeline import validation

    real = settings_overrides.build_settings

    def a_tree_whose_defaults_moved(overrides):  # type: ignore[no-untyped-def]
        return real(
            {
                "validation.alignment_threshold": 0.3,
                "validation.alignment_margin": 0.4,
                **overrides,
            }
        )

    monkeypatch.setattr(settings_overrides, "build_settings", a_tree_whose_defaults_moved)
    handed: list[object] = []
    monkeypatch.setattr(
        validation, "analyst_answer_checks", lambda _isr, inputs, **_kw: handed.append(inputs) or []
    )
    own = SimpleNamespace(listed=[], ledger_ids=set(), items=[], decompiled={}, image_bases={})
    run = _run({})
    run.identity = {"file_type": "pe", "platform": "windows"}
    with replay_environment({}):
        assert rules._analyst_checks(run, SimpleNamespace(), own, True, whole=False) == []
    inputs = handed[0]
    assert inputs.alignment_threshold == pytest.approx(0.3)  # type: ignore[attr-defined]
    assert inputs.alignment_margin == pytest.approx(0.4)  # type: ignore[attr-defined]


def test_an_agent_s_field_the_snapshot_lacks_is_the_tree_s_model_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.core.config import AgentDefinition

    assert rules._agent_setting(_run({}), "static", "attck_techniques") is True
    monkeypatch.setattr(AgentDefinition.model_fields["attck_techniques"], "default", False)
    assert rules._agent_setting(_run({}), "static", "attck_techniques") is False
    held = {"agents.definitions.static.attck_techniques": True}
    assert rules._agent_setting(_run(held), "static", "attck_techniques") is True


def test_the_rules_write_no_default_of_their_own_for_a_snapshot_read() -> None:
    source = inspect.getsource(rules)
    assert "else 0.05" not in source
    assert not re.search(r"attck_techniques\",\s*True\)", source)
