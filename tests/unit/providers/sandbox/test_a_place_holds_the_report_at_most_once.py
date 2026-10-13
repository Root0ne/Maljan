"""A mapped place holds the report at most once, and a path whose reading is not linear is named.

A descendant place path whose matches nest (``$..x`` where an ``x`` holds an
``x``) would write the inner matches again inside the outer ones each time the
document is written out. The values a place's kept matches hold, each counted
with what is nested in it, never exceed the values the report holds; past that
the place is cut and says so. A path that holds more than one descendant
segment reads the report once per node the first reached: the settings save
says so beside it, and never refuses it. So does a format read through a
mapping whose detect a built-in's overlaps: tried after every built-in, it
never reads a report both recognise.
"""

from __future__ import annotations

import gc
import json
import time
from collections.abc import Callable
from typing import Any

import pytest

from maljan.core.config import RestMappingConfig
from maljan.core.report_mapping import costly_paths, descendant_segments
from maljan.providers.sandbox.rest_mapping import (
    apply_mapping,
    compile_mapping,
    node_count,
    subtree_sizes,
)
from maljan.schemas.sandbox_document import sandbox_document


def _tree(depth: int) -> dict[str, Any]:
    """Processes nested ``depth`` deep, each holding the next under ``children``."""
    node: dict[str, Any] = {"pid": depth, "children": []}
    for pid in range(depth - 1, 0, -1):
        node = {"pid": pid, "children": [node]}
    return {"tree": node}


def _mapped(payload: dict[str, Any], places: dict[str, str]) -> Any:
    compiled = compile_mapping(RestMappingConfig(target_sha256="", places=places))
    return apply_mapping(compiled, payload, provider="rest", task_id="t")


class TestAPlaceHoldsTheReportAtMostOnce:
    def test_nested_matches_are_cut_at_the_report_s_size_and_say_so(self) -> None:
        payload = _tree(12)
        result = _mapped(payload, {"process_tree": "$..children[*]"})
        held = result.report.process_tree
        sizes = subtree_sizes(payload)
        assert sum(sizes.get(id(row), 1) for row in held) <= node_count(payload)
        assert result.stats["places.process_tree"].truncated is True
        written = len(json.dumps(sandbox_document(result.report)["behavior"]["processtree"]))
        assert written <= 2 * len(json.dumps(payload))

    def test_matches_that_do_not_nest_are_never_cut(self) -> None:
        payload = {"configs": [{"c2": f"192.0.2.{i}", "deep": {"x": [i]}} for i in range(500)]}
        result = _mapped(payload, {"extracted": "$..configs[*]"})
        assert len(result.report.extracted) == 500
        assert result.stats["places.extracted"].truncated is False

    def test_a_shallow_nested_tree_within_the_bound_is_kept_whole(self) -> None:
        payload = _tree(3)
        result = _mapped(payload, {"process_tree": "$..children[*]"})
        assert [row["pid"] for row in result.report.process_tree] == [2, 3]

    def test_the_sizes_count_a_shared_or_cyclic_container_once(self) -> None:
        shared = [1, 2, 3]
        payload: dict[str, Any] = {"a": shared, "b": shared}
        assert subtree_sizes(payload)[id(payload)] == 1 + 4 + 4
        loop: dict[str, Any] = {"x": 1}
        loop["self"] = loop
        assert subtree_sizes(loop)[id(loop)] >= 2


def _seconds(run: Callable[[], Any]) -> float:
    best = float("inf")
    for _ in range(2):
        gc.collect()
        gc.disable()
        try:
            started = time.perf_counter()
            run()
            best = min(best, time.perf_counter() - started)
        finally:
            gc.enable()
    return best


def test_the_bound_costs_time_linear_in_the_report() -> None:
    def run(n: int) -> Callable[[], Any]:
        payload = {"rows": [{"children": [{"v": i}]} for i in range(n)]}
        return lambda: _mapped(payload, {"memory": "$..children[*]"})

    once, tenfold = _seconds(run(2_000)), _seconds(run(20_000))
    assert tenfold <= 10 * once * 1.5 + 0.05, (once, tenfold)


class TestACostlyPathIsNamed:
    @pytest.mark.parametrize(
        ("path", "count"),
        [
            ("$.a[*]", 0),
            ("$..a", 1),
            ("$..a..b", 2),
            ("$..a[?@..b]", 2),
            ("$['x..y']..z", 1),
            ('$["a..b"][*]', 0),
        ],
    )
    def test_descendant_segments_are_counted_outside_quoted_names(
        self, path: str, count: int
    ) -> None:
        assert descendant_segments(path) == count

    def test_each_costly_path_of_a_mapping_is_named_by_its_field(self) -> None:
        mapping = RestMappingConfig(
            processes="$..procs..proc[*]",
            dns="$.dns[*]",
            channels={"linux.x": "$..a..b"},
            places={"extracted": "$..c[?@..d]"},
        )
        assert set(costly_paths(mapping)) == {"processes", "channels.linux.x", "places.extracted"}

    @pytest.mark.parametrize(
        ("path", "costly"),
        [
            ("$.a[*][?count($..x) > 0]", True),
            ("$.a[?count(@.b[?$..c]) > 0]", True),
            ("$.a[*][?@..x]", False),
            ("$.a[?@.b == '$..x']", False),
            ("$..a[?@.b]", False),
            ("$.a[?$.b == 1]", True),
            ("$.a[?count($.b[*]) > 0]", True),
            ("$.a[?@.v == $.b[0]]", True),
            ("$.a[?@.v == 1][?@.w == '$']", False),
        ],
    )
    def test_a_filter_holding_an_absolute_query_is_costly(self, path: str, costly: bool) -> None:
        warned = costly_paths(RestMappingConfig(processes=path))
        assert ("processes" in warned) is costly
        if costly:
            assert "every candidate" in warned["processes"]

    def test_an_absolute_wildcard_query_in_a_filter_is_quadratic_and_named(self) -> None:
        """The query from the root runs once per candidate: twice the rows, four times the work."""
        path = "$.a[?count($.b[*]) > 0]"
        assert "processes" in costly_paths(RestMappingConfig(processes=path))

        def run(n: int) -> Callable[[], Any]:
            payload = {
                "a": [{"v": i, "pid": i, "ppid": 0, "name": "x"} for i in range(n)],
                "b": list(range(n)),
            }
            compiled = compile_mapping(RestMappingConfig(target_sha256="", processes=path))
            return lambda: apply_mapping(compiled, payload, provider="rest", task_id="t")

        once, fourfold = _seconds(run(300)), _seconds(run(1_200))
        # Four times the rows: sixteen times the work where it is quadratic.
        assert fourfold > 6 * once, (once, fourfold)


def test_the_settings_save_warns_beside_a_costly_path_and_saves_it(monkeypatch: Any) -> None:
    import asyncio

    from app.api.v1 import settings as route
    from maljan.core.config import Settings

    settings = Settings(
        _env_file=None,  # type: ignore[call-arg]
        sandbox={
            "rest": {"mapping": {"places": {"memory": "$..m..n"}}},
            "report_formats": [
                {
                    "name": "acme_tree",
                    "detect": [[{"path": "/tree", "types": ["object"]}]],
                    "reader": "generic",
                    "mapping": {"processes": "$..p..q[*]"},
                }
            ],
        },
    )

    async def _effective(_db: Any) -> Settings:
        return settings

    monkeypatch.setattr(route, "effective_core_settings", _effective)
    warnings = asyncio.run(route._mapping_warnings(object(), {"core.sandbox.rest.mapping": {}}))
    assert set(warnings) == {
        "core.sandbox.rest.mapping.places.memory",
        "core.sandbox.report_formats.0.mapping.processes",
    }
    assert "anchor it" in warnings["core.sandbox.rest.mapping.places.memory"]
    assert asyncio.run(route._mapping_warnings(object(), {"llm.provider": "x"})) == {}


class TestAMappedFormatABuiltInOverlapsIsNamed:
    """A format read through a mapping is tried after every built-in: an overlap is said on save."""

    @staticmethod
    def _format(name: str, *tests: dict[str, Any], reader: str = "generic") -> Any:
        from maljan.core.report_formats import ReportFormat

        return ReportFormat.model_validate(
            {"name": name, "detect": [list(tests)], "reader": reader, "mapping": {}}
        )

    def test_a_detect_among_a_built_in_s_tests_is_named(self) -> None:
        from maljan.core.report_formats import builtin_overlapping

        older = self._format(
            "older_generic",
            {"path": "/info", "types": ["object"]},
            {"path": "/behavior", "types": ["object"]},
        )
        assert builtin_overlapping(older) == "cuckoo"

    def test_a_detect_whose_own_reports_a_built_in_claims_is_named(self) -> None:
        from maljan.core.report_formats import builtin_overlapping

        claimed = self._format(
            "claimed",
            {"path": "/CAPE", "types": ["object"]},
            {"path": "/acme", "types": ["string"]},
        )
        assert builtin_overlapping(claimed) == "cape2"

    def test_a_detect_of_its_own_is_not_named(self) -> None:
        from maljan.core.report_formats import builtin_overlapping

        own = self._format("own", {"path": "/acme_meta/version", "contains": "acme"})
        assert builtin_overlapping(own) == ""

    def test_a_partial_overlap_on_a_shared_place_is_named(self) -> None:
        from maljan.core.report_formats import builtin_overlapping, format_named

        # Every cuckoo-derived report carrying /signatures passes both detects.
        derived = self._format(
            "derived",
            {"path": "/info", "non_empty": True},
            {"path": "/signatures", "types": ["array"]},
        )
        cuckoo = format_named("cuckoo")
        assert cuckoo is not None
        assert builtin_overlapping(derived, [cuckoo]) == "cuckoo"
        # A CAPE report (/info an object) carrying /signatures passes it too,
        # but cuckoo's test on /info (a non-empty object) is the format's own:
        # the most specific built-in is named, not the first declared.
        assert builtin_overlapping(derived) == "cuckoo"

    def test_the_most_specific_built_in_is_named(self) -> None:
        from maljan.core.report_formats import builtin_overlapping

        derived = self._format(
            "derived",
            {"path": "/info", "types": ["object"], "non_empty": True},
            {"path": "/signatures", "types": ["array"]},
        )
        assert builtin_overlapping(derived) == "cuckoo"
        # Sharing a place with CAPE's own test names CAPE.
        versioned = self._format(
            "versioned",
            {"path": "/info", "types": ["object"]},
            {"path": "/info/version", "contains": "cape"},
            {"path": "/signatures", "types": ["array"]},
        )
        assert builtin_overlapping(versioned) == "cape2"

    @pytest.mark.parametrize(
        "apart",
        [
            {"path": "/info", "contains": "acme sandbox"},
            {"path": "/info", "types": ["string"]},
        ],
        ids=["text-it-never-holds", "another-type"],
    )
    def test_a_test_the_built_in_s_reports_cannot_pass_clears_it(
        self, apart: dict[str, Any]
    ) -> None:
        from maljan.core.report_formats import builtin_overlapping

        derived = self._format(
            "derived",
            {"path": "/info", "non_empty": True},
            {"path": "/signatures", "types": ["array"]},
            apart,
        )
        assert builtin_overlapping(derived) == ""

    def test_a_test_on_a_place_of_its_own_does_not_clear_it(self) -> None:
        from maljan.core.report_formats import builtin_overlapping

        # Every cuckoo report may carry /acme_marker too.
        derived = self._format(
            "derived",
            {"path": "/info", "non_empty": True},
            {"path": "/signatures", "types": ["array"]},
            {"path": "/acme_marker", "types": ["string"]},
        )
        assert builtin_overlapping(derived) == "cuckoo"

    def test_a_built_in_claiming_every_report_of_a_group_is_named_whatever_it_adds(self) -> None:
        from maljan.core.report_formats import ReportFormat, builtin_overlapping

        # The built-in reads any /run text; the format's /run text is one of them.
        mine = self._format("mine", {"path": "/run", "contains": "acme"})
        shipped = ReportFormat.model_validate(
            {"name": "shipped", "detect": [[{"path": "/run"}]], "reader": "generic"}
        )
        assert builtin_overlapping(mine, [shipped]) == "shipped"

    def test_a_partial_overlap_below_a_built_in_s_place_is_named(self) -> None:
        from maljan.core.report_formats import builtin_overlapping, format_named

        below = self._format(
            "below",
            {"path": "/info/id", "types": ["number"]},
            {"path": "/acme", "types": ["object"]},
        )
        cuckoo = format_named("cuckoo")
        assert cuckoo is not None
        assert builtin_overlapping(below, [cuckoo]) == "cuckoo"

    def test_a_built_in_s_place_below_a_format_s_is_named(self) -> None:
        from maljan.core.report_formats import ReportFormat, builtin_overlapping

        own = self._format("own_meta", {"path": "/meta", "types": ["object"]})
        builtin = ReportFormat.model_validate(
            {
                "name": "shipped",
                "detect": [[{"path": "/meta/engine", "contains": "x"}, {"path": "/run"}]],
                "reader": "generic",
            }
        )
        assert builtin_overlapping(own, [builtin]) == "shipped"

    def test_a_shared_place_both_cannot_hold_is_not_named(self) -> None:
        from maljan.core.report_formats import builtin_overlapping

        # cuckoo needs /info an object; a text there is no cuckoo report.
        text = self._format(
            "text_info",
            {"path": "/info", "types": ["string"]},
            {"path": "/signatures", "types": ["array"]},
        )
        assert builtin_overlapping(text) == ""

    def test_groups_sharing_no_place_are_not_named(self) -> None:
        from maljan.core.report_formats import builtin_overlapping

        apart = self._format(
            "apart",
            {"path": "/analysis_report", "types": ["object"]},
            {"path": "/infos", "types": ["object"]},
        )
        assert builtin_overlapping(apart) == ""

    @pytest.mark.parametrize("fixture", ["unread_flat_report.json", "unread_nested_report.json"])
    def test_an_accepted_proposal_is_not_named(self, fixture: str) -> None:
        from pathlib import Path

        from maljan.core.report_formats import ReportFormat, builtin_overlapping
        from maljan.core.report_proposals import propose_format

        path = Path(__file__).resolve().parents[3] / "fixtures" / "sandbox" / fixture
        declaration = propose_format(json.loads(path.read_text()))["declaration"]
        assert builtin_overlapping(ReportFormat.model_validate(declaration)) == ""

    def test_the_plainest_report_of_each_built_in_group_passes_it(self) -> None:
        from maljan.core.report_formats import BUILTIN_REPORT_FORMATS, least_report

        for fmt in BUILTIN_REPORT_FORMATS:
            for group in fmt.detect:
                report = least_report(group)
                assert report is not None and all(t.holds(report) for t in group), fmt.name

    def test_the_settings_save_warns_beside_the_detect_and_saves_it(self, monkeypatch: Any) -> None:
        import asyncio

        from app.api.v1 import settings as route
        from maljan.core.config import Settings

        settings = Settings(
            _env_file=None,  # type: ignore[call-arg]
            sandbox={
                "report_formats": [
                    {
                        "name": "older_generic",
                        "detect": [
                            [
                                {"path": "/info", "types": ["object"]},
                                {"path": "/behavior", "types": ["object"]},
                            ]
                        ],
                        "reader": "generic",
                        "mapping": {"processes": "$.behavior.processes[*]"},
                    },
                    {
                        "name": "own_reader",
                        "detect": [[{"path": "/behavior", "types": ["object"]}]],
                        "reader": "cuckoo",
                    },
                ],
            },
        )

        async def _effective(_db: Any) -> Settings:
            return settings

        monkeypatch.setattr(route, "effective_core_settings", _effective)
        warnings = asyncio.run(
            route._mapping_warnings(object(), {"core.sandbox.report_formats": []})
        )
        assert set(warnings) == {"core.sandbox.report_formats.0.detect"}
        assert "'cuckoo'" in warnings["core.sandbox.report_formats.0.detect"]
        assert "Saved as written" in warnings["core.sandbox.report_formats.0.detect"]


class TestTheOverlapIsSaidForTheSaveThatWritesTheDetect:
    """The warning beside a detect is said once, by the save that adds or changes it."""

    _DERIVED: dict[str, Any] = {
        "name": "derived",
        "detect": [[{"path": "/info", "non_empty": True}, {"path": "/signatures"}]],
        "reader": "generic",
        "mapping": {"processes": "$.behavior.processes[*]"},
    }

    def _warnings(
        self, monkeypatch: Any, changes: dict[str, Any], before: dict[str, Any] | None
    ) -> dict[str, str]:
        import asyncio

        from app.api.v1 import settings as route
        from maljan.core.config import Settings

        settings = Settings(
            _env_file=None,  # type: ignore[call-arg]
            sandbox={"report_formats": [self._DERIVED]},
        )

        async def _effective(_db: Any) -> Settings:
            return settings

        monkeypatch.setattr(route, "effective_core_settings", _effective)
        return asyncio.run(route._mapping_warnings(object(), changes, before))

    def _before(self, monkeypatch: Any) -> dict[str, Any] | None:
        import asyncio

        from app.api.v1 import settings as route
        from maljan.core.config import Settings

        settings = Settings(
            _env_file=None,  # type: ignore[call-arg]
            sandbox={"report_formats": [self._DERIVED]},
        )

        async def _effective(_db: Any) -> Settings:
            return settings

        monkeypatch.setattr(route, "effective_core_settings", _effective)
        return asyncio.run(route._declared_detects(object()))

    def test_a_save_adding_the_format_names_the_most_specific_built_in(
        self, monkeypatch: Any
    ) -> None:
        warnings = self._warnings(monkeypatch, {"core.sandbox.report_formats": []}, {})
        said = warnings["core.sandbox.report_formats.0.detect"]
        assert "'cuckoo'" in said and "'cape2'" not in said
        assert "/behavior, /info" in said

    def test_a_save_changing_the_detect_says_it_again(self, monkeypatch: Any) -> None:
        before = {"derived": [[{"path": "/info", "types": [], "non_empty": True, "contains": ""}]]}
        warnings = self._warnings(monkeypatch, {"core.sandbox.report_formats": []}, before)
        assert "core.sandbox.report_formats.0.detect" in warnings

    def test_a_save_leaving_the_detect_as_it_was_does_not_repeat_it(self, monkeypatch: Any) -> None:
        before = self._before(monkeypatch)
        assert before is not None and "derived" in before
        warnings = self._warnings(monkeypatch, {"core.sandbox.report_formats": []}, before)
        assert "core.sandbox.report_formats.0.detect" not in warnings

    @pytest.mark.parametrize(
        "changes",
        [{"core.sandbox.rest.mapping": {}}, {"core.sandbox.rest.base_url": "http://x"}],
    )
    def test_an_unrelated_sandbox_save_does_not_repeat_it(
        self, monkeypatch: Any, changes: dict[str, Any]
    ) -> None:
        assert "core.sandbox.report_formats.0.detect" not in self._warnings(
            monkeypatch, changes, None
        )

    def test_the_patch_route_says_it_for_a_new_detect_only(self, monkeypatch: Any) -> None:
        from unittest.mock import MagicMock

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.api.v1 import settings as route
        from app.database import get_db
        from app.deps import require_admin
        from app.services.settings_service import SaveResult
        from maljan.core.config import Settings

        state: dict[str, Any] = {"formats": []}

        async def _effective(_db: Any) -> Settings:
            return Settings(
                _env_file=None,  # type: ignore[call-arg]
                sandbox={"report_formats": state["formats"]},
            )

        async def _save(_self: Any, changes: dict[str, Any], **_kw: Any) -> Any:
            if "core.sandbox.report_formats" in changes:
                state["formats"] = changes["core.sandbox.report_formats"]
            return SaveResult(list(changes), {})

        async def _quiet(*_a: Any, **_kw: Any) -> Any:
            return {}

        async def _none(*_a: Any, **_kw: Any) -> list[str]:
            return []

        monkeypatch.setattr(route, "effective_core_settings", _effective)
        monkeypatch.setattr("app.services.settings_service.SettingsService.save", _save)
        monkeypatch.setattr(route, "_agent_warnings", _quiet)
        monkeypatch.setattr(route, "_unprobed_models_in", _none)
        app = FastAPI()
        app.include_router(route.router, prefix="/api/v1")
        app.dependency_overrides[get_db] = lambda: MagicMock()
        app.dependency_overrides[require_admin] = lambda: MagicMock(id=None)
        api = TestClient(app)

        def _patch(formats: list[dict[str, Any]]) -> dict[str, str]:
            answer = api.patch(
                "/api/v1/settings", json={"changes": {"core.sandbox.report_formats": formats}}
            )
            assert answer.status_code == 200, answer.text
            return answer.json()["warnings"]

        key = "core.sandbox.report_formats.0.detect"
        assert key in _patch([self._DERIVED])
        # The same detect with another mapping: not said again.
        remapped = {**self._DERIVED, "mapping": {"processes": "$.behavior.procs[*]"}}
        assert key not in _patch([remapped])
        # A changed detect that still overlaps: said again.
        changed = {**remapped, "detect": [[{"path": "/info", "non_empty": True}]]}
        assert key in _patch([changed])
