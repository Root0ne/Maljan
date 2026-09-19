"""Every transcript line says which stage said it, and under what name.

Two halves. The helpers are exercised directly; the emission sites are checked
by reading the source, because the thing that goes wrong here is a *new* one
being added without the stage — a message the console cannot group, which no
behavioural test would notice until somebody opened the conversation view and
found a line filed under nothing.

The whole-graph run in ``test_stage_events.py`` cannot stand in for this: a
mock analyst returns its canned result without taking the path that speaks, so
a mock run emits stage events and no conversation at all.
"""

from __future__ import annotations

import ast
from pathlib import Path

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.pipeline import nodes

_NODES = Path(nodes.__file__)


def _emissions() -> list[ast.Call]:
    """Every ``emit_agent_message(...)`` call in the pipeline's nodes."""
    tree = ast.parse(_NODES.read_text(encoding="utf-8"))
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "emit_agent_message"
    ]


def _keywords(call: ast.Call) -> set[str]:
    return {kw.arg for kw in call.keywords if kw.arg}


class TestEverySiteNamesItsStage:
    def test_the_nodes_speak_at_all(self) -> None:
        # A guard on the guard: a refactor that renamed the emitter would make
        # every assertion below vacuous.
        assert len(_emissions()) >= 8

    def test_every_line_the_pipeline_emits_names_a_stage(self) -> None:
        missing = [
            ast.unparse(call.keywords[0].value)
            for call in _emissions()
            if "stage" not in _keywords(call)
        ]
        assert missing == [], f"transcript lines emitted with no stage: {missing}"

    def test_the_verdict_and_the_system_notice_carry_their_kinds(self) -> None:
        kinds = {
            ast.unparse(kw.value)
            for call in _emissions()
            for kw in call.keywords
            if kw.arg == "kind"
        }
        assert {"'verdict'", "'system'"} <= kinds

    def test_an_agent_line_carries_the_label_its_definition_gives_it(self) -> None:
        labelled = [call for call in _emissions() if "display_name" in _keywords(call)]
        # The analyst's four outcomes and the reviser's two.
        assert len(labelled) >= 6


class TestTheHelpers:
    def test_a_stage_gives_its_key(self) -> None:
        class _Stage:
            key = "specialists"

        assert nodes.stage_key_of(_Stage(), "analysis") == "specialists"

    def test_a_node_with_no_stage_falls_back_to_the_name_of_its_kind(self) -> None:
        assert nodes.stage_key_of(None, "verdict") == "verdict"

    def test_a_stage_with_an_empty_key_falls_back_too(self) -> None:
        class _Stage:
            key = ""

        assert nodes.stage_key_of(_Stage(), "debate") == "debate"

    def test_a_label_comes_from_the_definition(self) -> None:
        container = ServiceContainer(Settings(_env_file=None), mock=True)
        assert nodes.label_of(container, "static") == "Static analyst"

    def test_an_operator_label_replaces_the_key(self) -> None:
        settings = Settings(_env_file=None)
        settings.agents.definitions["static"].label = "ahmet"
        container = ServiceContainer(settings, mock=True)
        assert nodes.label_of(container, "static") == "ahmet"

    def test_an_agent_with_no_definition_is_named_by_its_key(self) -> None:
        container = ServiceContainer(Settings(_env_file=None), mock=True)
        assert nodes.label_of(container, "nobody") == "nobody"

    def test_a_container_that_cannot_answer_costs_nothing(self) -> None:
        class _Broken:
            config = None

        assert nodes.label_of(_Broken(), "static") == "static"  # type: ignore[arg-type]
