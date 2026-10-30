"""A probe, an import and an unmigrated row read a server and its budgets as a run does (T-430).

A probe of a shipped server starts it with its seed's marks, as a run does. An
export written before the call budget moved keeps the floor it gave every
server, and its YARA timeout is the check budget. A store row a revision has
not moved yet is read as the key that now holds it.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

CAPA = "core.static.capa.timeout_seconds"
YARA = "core.static.yara.timeout_seconds"
BUDGET = "core.mcp.breaker.default_call_timeout_seconds"
CHECK = "core.reporting.detection_rule_check_seconds"
BEFORE = "maljan-settings/2"
MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261102000000_budgets_leave_the_static_blocks.py"
)


def _migration() -> Any:
    spec = importlib.util.spec_from_file_location("budgets_leave_the_static_blocks", MIGRATION)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestAProbeStartsAShippedServerAsARunDoes:
    def test_a_shipped_server_is_probed_with_its_seed_s_marks(self) -> None:
        from app.services.settings_probes import _probe_config
        from maljan.core.config import Settings

        for name, block in Settings(_env_file=None).mcp.servers.items():
            probed = _probe_config(block.model_dump(mode="json"), name)
            assert probed.shipped, name
            assert probed.attaches_as_builtin is block.attaches_as_builtin, name

    def test_an_operator_s_server_is_probed_as_theirs(self) -> None:
        from app.services.settings_probes import _probe_config

        probed = _probe_config({"transport": "stdio", "command": "x", "shipped": True}, "mine_q7")
        assert not probed.shipped
        assert not probed.attaches_as_builtin

    def test_the_probe_launches_a_shipped_sidecar_with_the_run_s_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.services.settings_probes import _probe_config
        from maljan.core.config import Settings
        from maljan.providers.servers import ServerHandle

        monkeypatch.delenv("PYTHONIOENCODING", raising=False)
        seen: list[dict[str, str]] = []

        class _FakeToolkit:
            def __init__(self, server_params: Any, **_kwargs: Any) -> None:
                seen.append(dict(server_params.env))

            async def initialize(self) -> None:
                return None

            def get_tools(self) -> list[Any]:
                return []

        monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _FakeToolkit)
        seed = Settings(_env_file=None).mcp.servers["analysis"]
        handle = ServerHandle("analysis", _probe_config(seed.model_dump(mode="json"), "analysis"))
        handle.open("probe")
        handle.close()

        assert seen and "PYTHONIOENCODING" not in seen[0]


class TestAnOlderExportKeepsItsFloor:
    @pytest.mark.parametrize(
        ("document", "budget", "check"),
        [
            ({CAPA: 900}, 900, None),
            ({YARA: 600}, 600, 600),
            ({CAPA: 900, YARA: 1200}, 1200, 1200),
            ({CAPA: 120}, 120, None),
        ],
    )
    def test_the_floor_and_the_check(
        self, document: dict[str, Any], budget: Any, check: Any
    ) -> None:
        from app.api.v1.settings import _imported_keys
        from maljan.core.settings_overrides import build_settings

        imported = _imported_keys(document, BEFORE)
        assert imported[BUDGET] == budget
        assert imported.get(CHECK) == check
        assert YARA not in imported
        settings = build_settings({key.removeprefix("core."): v for key, v in imported.items()})
        assert settings.mcp.breaker.default_call_timeout_seconds == budget
        assert settings.reporting.detection_rule_check_seconds == (check or 60)

    @pytest.mark.parametrize("document", [{CAPA: 300}, {YARA: 30}, {"core.llm.provider": "x"}])
    def test_nothing_is_added_where_the_floor_is_the_default(
        self, document: dict[str, Any]
    ) -> None:
        from app.api.v1.settings import _imported_keys

        assert BUDGET not in _imported_keys(document, BEFORE)

    def test_a_document_that_carries_the_budget_keeps_it(self) -> None:
        from app.api.v1.settings import _imported_keys

        assert _imported_keys({CAPA: 900, BUDGET: 45}, BEFORE)[BUDGET] == 45

    def test_a_document_this_release_wrote_keeps_its_static_timeouts_their_own(self) -> None:
        """capa raised to 900 on this release gives no server a 900 s budget on import."""
        from app.api.v1.settings import EXPORT_FORMAT, IMPORT_FORMATS, _imported_keys

        assert EXPORT_FORMAT == "maljan-settings/3"
        assert set(IMPORT_FORMATS) == {EXPORT_FORMAT, "maljan-settings/2", "maljan-settings/1"}
        assert _imported_keys({CAPA: 900}, EXPORT_FORMAT) == {CAPA: 900}
        assert _imported_keys({CAPA: 900}, "maljan-settings/2")[BUDGET] == 900
        assert _imported_keys({CAPA: 900}, "maljan-settings/1")[BUDGET] == 900
        # Its YARA timeout, written by an earlier release only, is still the check budget.
        assert _imported_keys({YARA: 30}, EXPORT_FORMAT) == {CHECK: 30}

    def test_the_console_writes_and_reads_the_same_formats(self) -> None:
        from app.api.v1.settings import EXPORT_FORMAT, IMPORT_FORMATS

        web = Path(__file__).resolve().parents[3] / "apps/web/src/types/settings.ts"
        text = web.read_text(encoding="utf-8")
        assert f'SETTINGS_EXPORT_FORMAT = "{EXPORT_FORMAT}"' in text
        for fmt in IMPORT_FORMATS:
            assert fmt == EXPORT_FORMAT or f'"{fmt}"' in text

    def test_a_save_never_derives_it(self) -> None:
        """A staged capa budget is capa's: the PATCH reads moved keys only."""
        from app.api.v1.settings import _current_keys

        assert BUDGET not in _current_keys({CAPA: 900})

    def test_the_migration_restates_the_core_floor(self) -> None:
        from maljan.core.legacy_tool_tables import FORMER_CALL_FLOOR_SOURCES, former_call_floor

        mod = _migration()
        assert mod.FLOOR_SOURCES == FORMER_CALL_FLOOR_SOURCES
        for held in ({}, {CAPA: 900}, {YARA: 1200}, {CAPA: 120, YARA: 30}, {CAPA: 120.5}):
            stored = {key: held.get(key) for key in FORMER_CALL_FLOOR_SOURCES}
            assert mod.floor(stored) == former_call_floor(held), held


class TestAnUnmovedRowIsReadAsItsNewKey:
    def test_the_yara_timeout_is_the_check_budget(self) -> None:
        from maljan.core.settings_overrides import build_settings

        settings = build_settings({"static.yara.timeout_seconds": 30})
        assert settings.reporting.detection_rule_check_seconds == 30

    def test_the_new_key_wins(self) -> None:
        from maljan.core.settings_overrides import build_settings

        settings = build_settings(
            {"static.yara.timeout_seconds": 30, "reporting.detection_rule_check_seconds": 15}
        )
        assert settings.reporting.detection_rule_check_seconds == 15

    @pytest.mark.parametrize("value", ["/", ""])
    def test_a_mirror_dir_its_model_refuses_is_still_refused(self, value: str) -> None:
        """A moved key its own model reads is left to it, as on dev."""
        from pydantic import ValidationError

        from maljan.core.settings_overrides import build_settings

        with pytest.raises(ValidationError):
            build_settings({"static.r2.mirror_dir": value})

    def test_a_mirror_dir_its_model_reads_is_read_as_on_dev(self) -> None:
        from maljan.core.settings_overrides import build_settings

        settings = build_settings({"static.r2.mirror_dir": "data/samples/r2-elsewhere"})
        assert settings.static.r2.work_dir == "r2-elsewhere"

    def test_the_flat_memory_keys_are_read_by_their_model_as_on_dev(self) -> None:
        from maljan.core.settings_overrides import build_settings

        settings = build_settings(
            {"memory.qdrant_url": "http://q:6333", "memory.qdrant_collection": "cases_q7"}
        )
        assert settings.memory.qdrant.url == "http://q:6333"
        assert settings.memory.qdrant.collection == "cases_q7"
        both = build_settings(
            {"memory.qdrant_url": "http://old:6333", "memory.qdrant.url": "http://new:6333"}
        )
        assert both.memory.qdrant.url == "http://new:6333"

    def test_the_store_moves_only_keys_no_model_reads(self) -> None:
        from maljan.core.settings_annotations import (
            MOVED_UNREAD_BY_MODELS,
            RENAMED_SETTING_VALUES,
            RENAMED_SETTINGS,
        )

        assert MOVED_UNREAD_BY_MODELS <= set(RENAMED_SETTINGS)
        assert not MOVED_UNREAD_BY_MODELS & set(RENAMED_SETTING_VALUES)
        assert not {k for k in MOVED_UNREAD_BY_MODELS if k.startswith("core.memory.")}

    def test_every_moved_key_is_read_as_its_new_one(self) -> None:
        from maljan.core.settings_annotations import RENAMED_SETTINGS, read_as_current

        for old, new in RENAMED_SETTINGS.items():
            assert new in read_as_current({old: "v"}), old
            bare_old, bare_new = old.removeprefix("core."), new.removeprefix("core.")
            assert bare_new in read_as_current({bare_old: "v"}, prefix=""), old
