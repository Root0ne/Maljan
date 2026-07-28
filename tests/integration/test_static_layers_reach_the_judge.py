"""The deterministic layers must actually be called, not merely exist.

Every unit test in this branch proves a layer works in isolation. None of them
prove the judge node calls it — and the judge node is where a Layer 0 either
contributes to the verdict or is dead code with passing tests.

That is not a theoretical concern here. `api_technique_hits` shipped declared on
the model, written by nothing, read by nothing, and every test passed. The
`tool_artifact` layer is wired the same way — one lazily-imported block inside
the judge, guarded by a config flag, in its own try/except — so the failure mode
is identical: flip the flag off by accident, or typo the config key, and the
layer silently never runs.

These tests exercise the wiring rather than the algorithms: the layers are
reachable through the container's real config, the judge's Layer-0 block writes
the keys the report node reads, and the state channel that carries them exists.
That last one has bitten before — `AnalysisState` is a TypedDict and LangGraph
drops any key not declared in it, silently, between nodes.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from maljan.core.config import get_settings
from maljan.core.paths import resolve_data
from maljan.pipeline import nodes
from maljan.pipeline.state import AnalysisState


class TestTheLayersAreReachableThroughRealConfig:
    def test_the_behaviour_catalog_resolves_from_config(self) -> None:
        cfg = get_settings().preprocessing
        assert cfg.use_api_behaviour_map is True
        path = resolve_data(cfg.api_behaviour_map_path)
        assert path.is_file(), f"catalog missing at {path}"

    def test_the_attck_catalog_resolves_from_config(self) -> None:
        cfg = get_settings().preprocessing
        assert cfg.use_api_attck_map is True
        assert resolve_data(cfg.api_attck_map_path).is_file()

    def test_the_tool_artifact_catalog_resolves_from_config(self) -> None:
        cfg = get_settings().preprocessing
        assert cfg.use_tool_artifacts is True
        assert resolve_data(cfg.tool_artifacts_path).is_file()

    def test_the_packer_and_language_catalogs_resolve(self) -> None:
        cfg = get_settings().preprocessing
        assert resolve_data(cfg.packer_signatures_path).is_file()
        assert resolve_data(cfg.language_signatures_path).is_file()

    def test_every_catalog_actually_loads(self) -> None:
        """A file that exists but parses to nothing is the same as no file, and
        the loaders are deliberately silent about it."""
        from maljan.analysis.api_capability_db import load_api_attck_map, load_api_behaviour_db
        from maljan.analysis.tool_artifact_layer import load_tool_artifacts

        cfg = get_settings().preprocessing
        behaviour = load_api_behaviour_db(str(resolve_data(cfg.api_behaviour_map_path)))
        attck = load_api_attck_map(str(resolve_data(cfg.api_attck_map_path)))
        tools = load_tool_artifacts(str(resolve_data(cfg.tool_artifacts_path)))

        assert behaviour is not None and len(behaviour) > 400
        assert attck is not None and len(attck) > 20
        assert tools is not None and len(tools) > 5


class TestTheJudgeNodeCallsThem:
    """Structural, because the alternative is a live LLM run per assertion.

    Each check pins one line of wiring that has no other guard: a lazily-imported
    layer inside a try/except cannot fail loudly, so if the call disappears the
    only symptom is a quieter report.
    """

    def test_the_tool_artifact_layer_is_invoked(self) -> None:
        source = inspect.getsource(nodes.make_judge_node)
        assert "build_tool_artifact_isr" in source
        assert 'isr_reports["tool_artifact"]' in source

    def test_the_import_capability_layer_is_invoked(self) -> None:
        source = inspect.getsource(nodes.make_judge_node)
        assert "build_import_capability_isr" in source
        assert 'isr_reports["import_capability"]' in source

    def test_the_yara_scan_sees_carved_payloads(self) -> None:
        """Without this the corpus only ever sees the packed outer shell."""
        source = inspect.getsource(nodes.make_judge_node)
        assert "carve_payloads" in source

    def test_the_judge_returns_the_tool_artifact_matches(self) -> None:
        source = inspect.getsource(nodes.make_judge_node)
        assert '"tool_artifact_matches"' in source

    def test_the_report_node_reads_them_back(self) -> None:
        source = inspect.getsource(nodes.make_report_node)
        assert 'state.get("tool_artifact_matches")' in source
        assert "attribution.tool_artifact_matches" in source


class TestTheStateChannelExists:
    def test_tool_artifact_matches_is_a_declared_channel(self) -> None:
        """LangGraph persists only keys declared in the TypedDict. An
        undeclared write is dropped between nodes with no error — the exact bug
        the F10 comment in state.py records for the sibling fields."""
        assert "tool_artifact_matches" in AnalysisState.__annotations__

    def test_the_app_initialises_it(self) -> None:
        """mypy catches a missing key at construction, but only while the
        TypedDict stays total."""
        source = (
            Path(inspect.getsourcefile(nodes) or "")
            .parent.parent.joinpath("app.py")
            .read_text(encoding="utf-8")
        )
        assert '"tool_artifact_matches": []' in source


class TestTheDeterministicAgentsAreKnownToTheCascade:
    def test_every_rule_layer_pools_by_max(self) -> None:
        """Mean pooling lets an LLM guess drag a rule match down. The set is a
        name check rather than a domain check because `import_capability`
        shares domain="static" with the LLM static analyst."""
        from maljan.analysis.ttp_cascade import _DETERMINISTIC_AGENTS

        for agent in ("import_capability", "tool_artifact", "lolbin", "network_dga"):
            assert agent in _DETERMINISTIC_AGENTS

    def test_they_are_also_skipped_by_the_attck_autocorrector(self) -> None:
        """Their IDs come from rule matches and are authoritative."""
        import maljan.memory.attck_validator as validator

        skip = (
            inspect.signature(validator.ATTCKValidator.correct_isr_reports)
            .parameters["skip_agents"]
            .default
        )
        assert "import_capability" in skip
        assert "tool_artifact" in skip
