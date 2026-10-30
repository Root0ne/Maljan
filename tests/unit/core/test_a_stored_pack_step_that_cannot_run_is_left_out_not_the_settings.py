"""A stored pack step this release cannot run is left out; the settings and other steps stand.

* Building the settings from the store leaves out a step whose server is gone,
  whose fields no longer validate, or whose renderer its tool's kind cannot
  feed; the shipped step it changed is in force again, the rest of the stored
  settings are kept, and one warning names it.
* A step that names a left-out step goes with it, in time linear in the list.
* The worker's job settings build the same way.
* Each step left out is listed once, with why, sanitised, for the console.
* A save that changes the steps is still refused, with the model's words; a
  stale stored step sent back as stored, matched by the whole item wherever it
  stands, blocks no unrelated save, and no other bad item rides on it; a step
  on a server of a refused map is not called unknown, the map's refusal
  standing for it.
* The renderer that reads declared facts is refused on a step whose tool is
  declared another kind, or none, unless the step declares the kind.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
from pydantic import ValidationError
from tests.linear_cost import assert_scales

from maljan.core import settings_overrides
from maljan.core.config import Settings
from maljan.core.pack_steps import effective_steps, lenient_steps, shipped_step
from maljan.core.settings_overrides import (
    build_settings,
    left_out_pack_steps,
    pack_step_refusals,
    pack_steps_left_out,
)

RULES = {
    "command": "invented-rules",
    "enabled": True,
    "tool_facts": {
        "match": {
            "kind": "capability_rules",
            "rows": "/hits/*",
            "values": {"rule": "/name"},
            "display_name": "RuleMatch",
        },
        "sig": {"kind": "signature_rules", "rows": "/hits/*", "values": {"rule": "/name"}},
        "plain": {"rows": "/hits/*", "values": {"rule": "/name"}},
    },
}
GOOD = {"id": "extra", "server": "rules", "tool": "match"}
GONE = {"id": "lost", "server": "nowhere", "tool": "t"}


def _stored(*steps: Any, **more: Any) -> dict[str, Any]:
    return {"mcp.servers": {"rules": RULES}, "triage.steps": list(steps), **more}


def _ids(settings: Settings) -> list[str]:
    return [step.id for step in effective_steps(settings.triage.steps)]


@pytest.fixture(autouse=True)
def _fresh_warnings() -> None:
    settings_overrides._WARNED_STEPS.clear()


class TestAStoredStepThatCannotRunIsLeftOut:
    def test_a_step_on_a_server_gone_is_left_out_and_the_rest_stand(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            built = build_settings(_stored(GONE, GOOD, **{"triage.budget_seconds": 77}))
        assert "lost" not in _ids(built) and "extra" in _ids(built)
        assert built.triage.budget_seconds == 77
        assert "rules" in built.mcp.servers
        said = [r.getMessage() for r in caplog.records if "triage pack step" in r.getMessage()]
        assert len(said) == 1 and "lost" in said[0]

    def test_a_changed_shipped_step_falls_back_to_the_shipped_one(self) -> None:
        swapped = {"id": "capa", "server": "nowhere", "tool": "t"}
        built = build_settings(_stored(swapped, GOOD))
        (capa,) = [step for step in effective_steps(built.triage.steps) if step.id == "capa"]
        assert capa == shipped_step("capa")
        assert "extra" in _ids(built)

    def test_a_step_whose_fields_no_longer_validate_is_left_out(self) -> None:
        built = build_settings(_stored({"id": "odd", "enabled": "maybe", "x": 1}, GOOD, "text"))
        assert "odd" not in _ids(built) and "extra" in _ids(built)
        assert left_out_pack_steps(_stored({"id": "odd", "x": 1}, GOOD, "text")) == [
            "odd",
            "#2",
        ]

    def test_a_step_naming_a_left_out_step_goes_with_it(self) -> None:
        after = {"id": "next", "server": "rules", "tool": "match", "after": "lost"}
        built = build_settings(_stored(GONE, after, GOOD))
        assert "next" not in _ids(built) and "extra" in _ids(built)

    def test_a_renderer_its_tool_s_kind_cannot_feed_is_left_out(self) -> None:
        step = {"id": "s", "server": "rules", "tool": "sig", "renderer": "capability_rules"}
        assert left_out_pack_steps(_stored(step, GOOD)) == ["s"]

    def test_a_valid_list_is_read_as_it_was_saved(self) -> None:
        stored = _stored({"id": "capa", "budget_seconds": 100}, GOOD)
        built = build_settings(stored)
        token = settings_overrides.STORE_ONLY.set(True)
        try:
            strict = Settings(**settings_overrides.nest(stored))
        finally:
            settings_overrides.STORE_ONLY.reset(token)
        assert effective_steps(built.triage.steps) == effective_steps(strict.triage.steps)
        assert left_out_pack_steps(stored) == []

    def test_the_worker_builds_the_job_s_settings_the_same_way(self) -> None:
        from app.worker.analysis_worker import build_job_settings

        built = build_job_settings(_stored(GONE, GOOD), {"max_iterations": 2})
        assert "extra" in _ids(built) and "lost" not in _ids(built)
        assert built.negotiation.max_iterations == 2

    def test_a_long_chain_is_left_out_in_linear_time(self) -> None:
        def chain(n: int) -> list[dict[str, Any]]:
            steps = [GONE]
            steps += [
                {"id": f"c{i}", "server": "rules", "tool": "match", "after": f"c{i - 1}"}
                if i
                else {"id": "c0", "server": "rules", "tool": "match", "after": "lost"}
                for i in range(n)
            ]
            return steps

        def problem(step: Any) -> str:
            return "gone" if step.server == "nowhere" else ""

        def left_out(value: list[dict[str, Any]]) -> None:
            kept, left = lenient_steps(value, problem)
            assert kept == [] and len(left) == len(value)

        left_out(chain(50))
        assert_scales(chain, 300, left_out, factor=10, repeats=5)
        assert_scales(chain, 600, left_out, factor=5, repeats=5)


class TestEachLeftOutStepSaysWhy:
    def test_a_step_on_a_server_gone_names_the_server(self) -> None:
        said = pack_steps_left_out(_stored(GONE, GOOD))
        assert list(said) == ["lost"]
        assert "references unknown mcp server 'nowhere'" in said["lost"]

    def test_a_step_naming_a_left_out_step_names_it(self) -> None:
        after = {"id": "next", "server": "rules", "tool": "match", "after": "lost"}
        said = pack_steps_left_out(_stored(GONE, after))
        assert said["next"] == "step 'next' names step 'lost', which is left out"

    def test_a_field_that_does_not_validate_is_named(self) -> None:
        said = pack_steps_left_out(_stored({"id": "odd", "enabled": "maybe"}, "text"))
        assert said["odd"].startswith("enabled: ")
        assert "#1" in said

    def test_a_step_declared_twice_is_listed_once(self) -> None:
        stored = _stored(GOOD, GOOD)
        assert left_out_pack_steps(stored) == ["extra"]
        assert pack_steps_left_out(stored) == {
            "extra": "step 'extra' is declared more than once; the first is read"
        }

    def test_a_stored_value_that_is_no_list_is_named(self) -> None:
        said = pack_steps_left_out({"triage.steps": "text"})
        assert said == {"triage.steps": "the stored steps are not a list"}

    def test_what_an_operator_wrote_is_sanitised(self) -> None:
        said = pack_steps_left_out(_stored({"id": "a\nb\x1b", "x": 1}))
        assert list(said) == ["a\\nb\\x1b"]
        assert all("\n" not in text and "\x1b" not in text for text in said.values())

    def test_a_reset_of_the_server_a_step_calls_is_listed(self) -> None:
        stored = _stored(GOOD)
        assert pack_steps_left_out(stored) == {}
        reset = {key: value for key, value in stored.items() if key != "mcp.servers"}
        said = pack_steps_left_out(reset)
        assert "references unknown mcp server 'rules'" in said["extra"]


class TestASaveIsStillStrict:
    def test_a_save_that_adds_a_step_that_cannot_run_is_refused(self) -> None:
        refused = pack_step_refusals(_stored(GONE, GOOD), _stored(GOOD))
        assert (
            "triage step 'lost' references unknown mcp server 'nowhere'"
            in (refused["core.triage.steps"])
        )

    def test_a_stale_step_sent_back_as_stored_blocks_no_unrelated_save(self) -> None:
        current = _stored(GONE, GOOD)
        merged = {**current, "triage.budget_seconds": 90}
        assert pack_step_refusals(merged, current) == {}

    def test_changing_a_stale_step_is_held_to_the_rules(self) -> None:
        current = _stored(GONE, GOOD)
        merged = _stored({**GONE, "tool": "other"}, GOOD)
        assert "core.triage.steps" in pack_step_refusals(merged, current)

    def test_a_different_bad_item_in_a_stale_item_s_place_is_refused(self) -> None:
        current = _stored({"x": 1}, GOOD)
        assert left_out_pack_steps(current) == ["#0"]
        assert pack_step_refusals(_stored({"y": 2}, GOOD), current)
        assert pack_step_refusals({**current, "triage.budget_seconds": 90}, current) == {}

    def test_a_stale_item_moved_elsewhere_is_still_the_stored_one(self) -> None:
        current = _stored({"x": 1}, GOOD)
        assert pack_step_refusals(_stored(GOOD, {"x": 1}), current) == {}

    def test_a_bad_copy_of_a_step_stored_twice_is_refused(self) -> None:
        current = _stored(GOOD, GOOD)
        assert left_out_pack_steps(current) == ["extra"]
        assert pack_step_refusals(_stored({**GOOD, "enabled": "maybe"}, GOOD), current)
        assert pack_step_refusals(_stored(GOOD, {**GOOD, "tool": "sig"}), current)
        assert pack_step_refusals(_stored(GOOD, GOOD, GOOD), current)
        assert pack_step_refusals(_stored(GOOD, GOOD), current) == {}

    def test_a_step_on_a_server_of_a_refused_map_is_not_called_unknown(self) -> None:
        on_refused = {"id": "on_refused", "server": "refused", "tool": "t"}
        servers = {"rules": RULES, "refused": {"command": "x", "enabled": "maybe"}}
        merged = {"mcp.servers": servers, "triage.steps": [GOOD, on_refused]}
        assert pack_step_refusals(merged, {}) == {}
        said = pack_step_refusals({**merged, "triage.steps": [GOOD, on_refused, GONE]}, {})
        assert said == {
            "core.triage.steps": "lost: triage step 'lost' references unknown mcp server 'nowhere'"
        }

    def test_a_step_on_a_server_of_a_refused_map_is_listed_saying_why(self) -> None:
        on_refused = {"id": "on_refused", "server": "refused", "tool": "t"}
        servers = {"rules": RULES, "refused": {"command": "x", "enabled": "maybe"}}
        stored = {"mcp.servers": servers, "triage.steps": [GOOD, on_refused]}
        said = pack_steps_left_out(stored)
        assert list(said) == ["on_refused"]
        assert "stored entry of its server 'refused' is refused" in said["on_refused"]
        assert "unknown" not in said["on_refused"]
        assert left_out_pack_steps(stored) == ["on_refused"]

    @pytest.mark.parametrize(
        "step",
        [
            pytest.param({"id": "refused", "server": "nowhere", "tool": "t"}, id="its-id"),
            pytest.param({"id": "s", "server": "nowhere", "tool": "refused"}, id="its-tool"),
            pytest.param(
                {"id": "s", "server": "nowhere", "tool": "t", "after": "refused"}, id="another"
            ),
        ],
    )
    def test_only_the_step_s_server_is_matched_to_a_refused_entry(
        self, step: dict[str, Any]
    ) -> None:
        servers = {"rules": RULES, "refused": {"command": "x", "enabled": "maybe"}}
        merged = {"mcp.servers": servers, "triage.steps": [GOOD, step]}
        said = pack_step_refusals(merged, {})
        assert "references unknown mcp server 'nowhere'" in said["core.triage.steps"]
        listed = pack_steps_left_out(merged)
        assert "references unknown mcp server 'nowhere'" in listed[step["id"]]

    def test_steps_are_listed_where_another_stored_setting_does_not_build(self) -> None:
        stored = _stored(GONE, GOOD, **{"triage.budget_seconds": 0})
        assert list(pack_steps_left_out(stored)) == ["lost"]
        assert left_out_pack_steps(stored) == ["lost"]

    def test_a_save_that_can_run_its_steps_passes(self) -> None:
        assert pack_step_refusals(_stored(GOOD), {}) == {}


class TestTheDeclaredFactRendererNeedsItsKind:
    def _settings(self, step: dict[str, Any]) -> Settings:
        return Settings(_env_file=None, mcp={"servers": {"rules": RULES}}, triage={"steps": [step]})

    @pytest.mark.parametrize("tool", ["sig", "plain"])
    def test_a_tool_of_another_kind_or_none_is_refused(self, tool: str) -> None:
        step = {"id": "s", "server": "rules", "tool": tool, "renderer": "capability_rules"}
        with pytest.raises(ValidationError) as caught:
            self._settings(step)
        assert "renderer 'capability_rules' reads the declared facts of a tool of kind" in str(
            caught.value
        )

    def test_a_platform_step_of_another_kind_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            Settings(
                _env_file=None, triage={"steps": [{"id": "hashes", "renderer": "capability_rules"}]}
            )

    def test_a_tool_of_the_kind_or_a_step_declaring_it_is_saved(self) -> None:
        own = {"id": "s", "server": "rules", "tool": "match", "renderer": "capability_rules"}
        declared = {
            "id": "t",
            "server": "rules",
            "tool": "plain",
            "renderer": "capability_rules",
            "kind": "capability_rules",
        }
        for step in (own, declared):
            assert step["id"] in _ids(self._settings(step))

    def test_the_shipped_matcher_keeps_its_renderer(self) -> None:
        assert "capa" in _ids(Settings(_env_file=None, triage={"steps": [{"id": "capa"}]}))
