"""The console lists the installed provider plugins and saves a plugin's id by the list it leaves.

``GET /settings/plugins`` reads package metadata only, so listing a plugin
imports nothing of it. A provider id is saved when it is a shipped one or an
installed plugin of its kind that the allow-list the save leaves names, read
from metadata, never from what the API process has loaded, and the worker
judges the stored settings alike. A save that drops a plugin a provider id
still selects is refused, naming the keys. The API loads a plugin only where
it runs that plugin's own code, that plugin alone, off its event loop and for
a bounded wait: the settings pages, and a save, reset or import that writes
no plugin's own block, import nothing, so a plugin whose import ends the
process can still be removed. A running job keeps the plugins it started
with, and the command line reads its settings after loading its plugins.
Only an administrator lists plugins or changes the list, and a change is
logged with who made it.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.unit._plugin_doubles import (
    AcmeLLM,
    AcmeSandbox,
    AcmeStatic,
    FakePoint,
    allow,
    ends_the_process,
    installed_plugins,
    llm_with_block,
    memory_plugin,
    withdraw_every_plugin,
)

from app.api.v1.settings import router
from app.database import get_db
from app.deps import require_active_user, require_admin
from app.models.user import UserRole
from app.services import plugins as api_plugins
from app.services import settings_service as svc
from maljan.core import plugins
from maljan.core.config import Settings
from maljan.providers import registry

ADMIN_ID = "00000000-0000-0000-0000-000000000001"


@pytest.fixture
def installed(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, list[FakePoint]]]:
    yield installed_plugins(monkeypatch)
    withdraw_every_plugin()


def _app(role: UserRole = UserRole.ADMIN, db: Any = None) -> FastAPI:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    if role is UserRole.ADMIN:
        app.dependency_overrides[require_admin] = lambda: MagicMock(id=ADMIN_ID, role=role)
    else:
        app.dependency_overrides[require_active_user] = lambda: MagicMock(role=role)
    session = db if db is not None else MagicMock()
    app.dependency_overrides[get_db] = lambda: session
    return app


def _stored(values: dict[str, Any]) -> Any:
    return patch(
        "app.services.plugins.SettingsService.load_overrides", AsyncMock(return_value=values)
    )


def _db(rows: dict[str, Any], secret: frozenset[str] = frozenset()) -> Any:
    """A database session holding ``rows`` as stored settings; the ``secret`` keys as secrets."""
    held = [
        SimpleNamespace(key=k, value=v, is_secret=k in secret, updated_at=None, updated_by=None)
        for k, v in rows.items()
    ]
    db = MagicMock()
    db.execute = AsyncMock(
        return_value=SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: list(held)))
    )
    db.add = MagicMock()
    db.delete = AsyncMock()
    db.commit = AsyncMock()
    return db


class TestTheListingRoute:
    def test_each_kind_is_listed_from_metadata_and_nothing_is_imported(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        point = FakePoint("acme", AcmeStatic, dist="maljan-acme", version="1.2.3")
        installed["static"].append(point)
        with _stored({}):
            r = TestClient(_app()).get("/api/v1/settings/plugins")
        assert r.status_code == 200
        body = r.json()
        assert body["allow_list_key"] == "core.plugins.allowed"
        assert [kind["kind"] for kind in body["kinds"]] == ["llm", "static", "sandbox", "memory"]
        static = body["kinds"][1]
        assert static["group"] == "maljan.static_providers"
        assert static["plugins"] == [
            {
                "name": "acme",
                "entry": "static:acme",
                "distribution": "maljan-acme",
                "version": "1.2.3",
                "allowed": False,
                "state": "not_allowed",
                "error": "",
                "api_state": "",
                "api_error": "",
            }
        ]
        assert point.loads == 0

    def test_an_allowed_plugin_is_listed_allowed_and_loaded_by_nothing(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        point = FakePoint("acme", AcmeStatic)
        installed["static"].append(point)
        with _stored({"core.plugins.allowed": ["static:acme"]}):
            body = TestClient(_app()).get("/api/v1/settings/plugins").json()
        (row,) = body["kinds"][1]["plugins"]
        assert (row["allowed"], row["state"], row["api_state"]) == (True, "allowed", "")
        assert point.loads == 0

    def test_the_api_s_own_load_is_named_as_the_api_s(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        installed["llm"].append(FakePoint("broken_llm", ImportError("no client")))
        installed["memory"].append(FakePoint("vectorhub", memory_plugin("vectorhub")))
        installed["sandbox"].append(FakePoint("cape2", AcmeSandbox, dist="cape2-clone"))
        allowed = ["llm:broken_llm", "memory:vectorhub", "sandbox:cape2", "static:gone"]
        allow(*allowed)
        with _stored({"core.plugins.allowed": allowed}):
            body = TestClient(_app()).get("/api/v1/settings/plugins").json()
        by_kind = {kind["kind"]: kind for kind in body["kinds"]}
        (broken,) = by_kind["llm"]["plugins"]
        assert (broken["state"], broken["api_state"]) == ("allowed", "failed")
        assert broken["api_error"] == "ImportError: no client"
        (vectorhub,) = by_kind["memory"]["plugins"]
        assert vectorhub["api_state"] == "loaded"
        (clash,) = by_kind["sandbox"]["plugins"]
        assert clash["state"] == "refused" and "built-in sandbox provider" in clash["error"]
        assert by_kind["static"]["allowed_absent"] == ["gone"]

    def test_only_an_administrator_lists_them(self, installed: dict[str, list[FakePoint]]) -> None:
        installed["static"].append(FakePoint("acme", AcmeStatic))
        r = TestClient(_app(UserRole.ANALYST)).get("/api/v1/settings/plugins")
        assert r.status_code == 403


class TestChangingTheAllowList:
    def test_only_an_administrator_changes_it(self) -> None:
        save = AsyncMock()
        with patch("app.api.v1.settings.SettingsService.save", save):
            r = TestClient(_app(UserRole.ANALYST)).patch(
                "/api/v1/settings", json={"changes": {"core.plugins.allowed": ["llm:acme"]}}
            )
        assert r.status_code == 403
        save.assert_not_awaited()

    def test_a_save_loads_nothing_after_it_and_waits_for_nothing_it_allows(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        point = FakePoint("acme_llm", AcmeLLM)
        installed["llm"].append(point)
        result = svc.SaveResult(applied=["core.plugins.allowed"], applies={"next_job": 1})
        with (
            patch("app.api.v1.settings.SettingsService.save", AsyncMock(return_value=result)),
            patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})),
            patch("app.api.v1.settings._agent_warnings", AsyncMock(return_value={})),
            patch("app.api.v1.settings._mapping_warnings", AsyncMock(return_value={})),
            patch("app.api.v1.settings._unprobed_models_in", AsyncMock(return_value=[])),
        ):
            r = TestClient(_app()).patch(
                "/api/v1/settings", json={"changes": {"core.plugins.allowed": ["llm:acme_llm"]}}
            )
        assert r.status_code == 200
        assert point.loads == 0

    @pytest.mark.asyncio
    async def test_a_change_is_logged_with_who_made_it(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr(svc, "_audit", AsyncMock())
        user = uuid.uuid4()
        with caplog.at_level(logging.INFO):
            await svc.SettingsService(_db({})).save(
                {"core.plugins.allowed": ["llm:acme"]}, user_id=user, ip=None
            )
        assert (
            f"The plugin allow-list was changed by user {user}: it named no plugin and names "
            "llm:acme." in caplog.text
        )
        svc._audit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_the_stored_list_is_the_one_this_process_judges_by(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        point = FakePoint("acme", AcmeStatic)
        installed["static"].append(point)
        await svc.SettingsService(_db({"core.plugins.allowed": ["static:acme"]})).load_overrides()
        assert plugins.allow_list() == frozenset({"static:acme"})
        assert "acme" not in registry.static_provider_ids()
        assert point.loads == 0


def _service() -> svc.SettingsService:
    return svc.SettingsService(db=None)  # type: ignore[arg-type]


KINDS = [
    ("core.llm.provider", "llm", "acme_llm", AcmeLLM),
    ("core.static.provider", "static", "acme_static", AcmeStatic),
    ("core.sandbox.provider", "sandbox", "acme_sandbox", AcmeSandbox),
    ("core.memory.backend", "memory", "acme_memory", None),
]


def _point(name: str, provides: Any) -> FakePoint:
    return FakePoint(name, provides if provides is not None else memory_plugin(name))


class TestSavingAProviderId:
    @pytest.mark.parametrize(("key", "kind", "name", "provides"), KINDS)
    def test_an_allowed_installed_plugin_is_accepted_without_importing_it(
        self, installed: dict[str, list[FakePoint]], key: str, kind: str, name: str, provides: Any
    ) -> None:
        point = _point(name, provides)
        installed[kind].append(point)
        stored = {"core.plugins.allowed": [f"{kind}:{name}"]}
        assert _service().check_keys({key: name}, stored) is None
        assert point.loads == 0

    @pytest.mark.parametrize(("key", "kind", "name", "provides"), KINDS)
    def test_one_save_may_allow_a_plugin_and_select_it(
        self, installed: dict[str, list[FakePoint]], key: str, kind: str, name: str, provides: Any
    ) -> None:
        installed[kind].append(_point(name, provides))
        changes = {"core.plugins.allowed": [f"{kind}:{name}"], key: name}
        assert _service().check_keys(changes, {}) is None

    @pytest.mark.parametrize(("key", "kind", "name", "provides"), KINDS)
    def test_one_save_may_not_drop_a_plugin_and_select_it_though_the_api_loaded_it(
        self, installed: dict[str, list[FakePoint]], key: str, kind: str, name: str, provides: Any
    ) -> None:
        installed[kind].append(_point(name, provides))
        allow(f"{kind}:{name}")
        stored = {"core.plugins.allowed": [f"{kind}:{name}"]}
        with pytest.raises(svc.SettingsValidationError) as refused:
            _service().check_keys({"core.plugins.allowed": [], key: name}, stored)
        assert f"allow {kind}:{name} to load it" in refused.value.errors[key]

    @pytest.mark.parametrize(("key", "kind", "name", "provides"), KINDS)
    def test_an_installed_plugin_the_list_does_not_name_is_refused_naming_the_list(
        self, installed: dict[str, list[FakePoint]], key: str, kind: str, name: str, provides: Any
    ) -> None:
        installed[kind].append(_point(name, provides))
        with pytest.raises(svc.SettingsValidationError) as refused:
            _service().check_keys({key: name}, {"core.plugins.allowed": []})
        said = refused.value.errors[key]
        assert said.startswith("not one of: ")
        assert "plugin allow-list (core.plugins.allowed) does not name" in said

    def test_an_unknown_id_is_refused_naming_how_a_plugin_is_accepted(self) -> None:
        with pytest.raises(svc.SettingsValidationError) as refused:
            _service().check_keys({"core.static.provider": "nothing"}, {})
        assert (
            "an installed static plugin is accepted once the plugin allow-list "
            "(core.plugins.allowed) names it as static:<name>"
        ) in refused.value.errors["core.static.provider"]

    def test_a_name_two_packages_declare_is_refused_with_that_cause(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        installed["static"] += [
            FakePoint("acme_static", AcmeStatic, dist="maljan-acme"),
            FakePoint("acme_static", AcmeStatic, dist="acme-fork"),
        ]
        stored = {"core.plugins.allowed": ["static:acme_static"]}
        with pytest.raises(svc.SettingsValidationError) as refused:
            _service().check_keys({"core.static.provider": "acme_static"}, stored)
        said = refused.value.errors["core.static.provider"]
        assert "two installed packages declare it" in said and "accepted once" not in said

    def test_an_agent_naming_an_allowed_static_plugin_is_saved_by_the_list_it_leaves(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        from app.services.agent_map import AGENT_DEFINITIONS_KEY, AgentMapError, validate_agent_map

        point = FakePoint("acme_static", AcmeStatic)
        installed["static"].append(point)
        definitions = {
            "checker": {
                "role": "generic",
                "label": "Checker",
                "prompt": "p",
                "static_provider": "acme_static",
            }
        }
        changes = {AGENT_DEFINITIONS_KEY: definitions}
        with pytest.raises(AgentMapError) as refused:
            validate_agent_map(changes, {})
        said = refused.value.errors[f"{AGENT_DEFINITIONS_KEY}.checker.static_provider"]
        assert "plugin allow-list" in said
        stored = {"core.plugins.allowed": ["static:acme_static"]}
        assert AGENT_DEFINITIONS_KEY in validate_agent_map(changes, stored)
        # Loaded in this process, and dropped by the save: refused all the same.
        allow("static:acme_static")
        with pytest.raises(AgentMapError):
            validate_agent_map({**changes, "core.plugins.allowed": []}, stored)
        assert point.loads == 1

    def test_a_job_may_name_an_allowed_installed_plugin(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        from pydantic import ValidationError

        from app.schemas.job import JobCreateRequest

        installed["sandbox"].append(FakePoint("acme_sandbox", AcmeSandbox))
        sample = uuid.uuid4()
        with pytest.raises(ValidationError, match="plugin allow-list"):
            JobCreateRequest(sample_id=sample, config={"sandbox_provider": "acme_sandbox"})
        plugins.install_allow_list(["sandbox:acme_sandbox"])
        JobCreateRequest(sample_id=sample, config={"sandbox_provider": "acme_sandbox"})


class TestADroppedPluginStillSelectedIsRefused:
    @pytest.mark.asyncio
    async def test_a_save_that_drops_it_names_each_key_that_selects_it(
        self, installed: dict[str, list[FakePoint]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(svc, "_audit", AsyncMock())
        installed["static"].append(FakePoint("acme_static", AcmeStatic))
        rows = {
            "core.plugins.allowed": ["static:acme_static"],
            "core.static.provider": "acme_static",
        }
        db = _db(rows)
        with pytest.raises(svc.SettingsValidationError) as refused:
            await svc.SettingsService(db).save(
                {"core.plugins.allowed": []}, user_id=uuid.uuid4(), ip=None
            )
        assert "drops from the plugin allow-list" in refused.value.errors["core.static.provider"]
        assert "core.static.provider" in refused.value.errors["core.plugins.allowed"]
        db.commit.assert_not_awaited()
        # The same save with another provider selected goes through.
        await svc.SettingsService(_db(rows)).save(
            {"core.plugins.allowed": [], "core.static.provider": "ghidra"},
            user_id=uuid.uuid4(),
            ip=None,
        )

    @pytest.mark.asyncio
    async def test_a_reset_of_the_list_is_refused_the_same_way(
        self, installed: dict[str, list[FakePoint]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(svc, "_audit", AsyncMock())
        installed["memory"].append(FakePoint("vectorhub", memory_plugin("vectorhub")))
        db = _db({"core.plugins.allowed": ["memory:vectorhub"], "core.memory.backend": "vectorhub"})
        with pytest.raises(svc.SettingsValidationError) as refused:
            await svc.SettingsService(db).reset(
                ["core.plugins.allowed"], user_id=uuid.uuid4(), ip=None
            )
        assert "core.memory.backend" in refused.value.errors
        db.delete.assert_not_awaited()


# (kind, the setting that selects it, its name, the job option that names it)
JUDGED = [
    ("static", "static.provider", "acme_static", "static_provider"),
    ("sandbox", "sandbox.provider", "acme_sandbox", "sandbox_provider"),
    ("llm", "llm.provider", "acme_llm", "llm_provider"),
    ("memory", "memory.backend", "acme_memory", None),
]


def _judged_point(kind: str, name: str) -> FakePoint:
    provides: Any = {
        "static": AcmeStatic,
        "sandbox": AcmeSandbox,
        "llm": llm_with_block(name),
        "memory": memory_plugin(name),
    }[kind]
    return FakePoint(name, provides)


def _what_the_worker_builds(kind: str, built: Any) -> Any:
    """What a job builds from its settings for a provider of ``kind``; a refusal raises."""
    if kind == "static":
        return registry.get_static_provider(built)
    if kind == "sandbox":
        return registry.get_sandbox_provider(built)
    if kind == "llm":
        from maljan.llm.registry import LLMProviderRegistry

        return LLMProviderRegistry(built).build_model("expert")
    from maljan.memory.store_factory import build_memory_store

    return build_memory_store(built)


class TestTheApiAndTheWorkerJudgeAlike:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("loaded", [False, True])
    @pytest.mark.parametrize(("kind", "selector", "name", "option"), JUDGED)
    async def test_what_a_save_accepts_the_worker_runs_and_what_it_refuses_the_worker_refuses(
        self,
        installed: dict[str, list[FakePoint]],
        monkeypatch: pytest.MonkeyPatch,
        kind: str,
        selector: str,
        name: str,
        option: str | None,
        loaded: bool,
    ) -> None:
        from app.services.agent_map import AGENT_DEFINITIONS_KEY
        from app.worker.analysis_worker import build_job_settings, take_the_job_plugin_set
        from maljan.core.exceptions import LLMError, MemoryStoreError
        from maljan.providers.errors import ProviderConfigurationError

        # The refusals the worker turns into a failed job, and nothing else: a
        # crash on either side fails this test.
        worker_refusals = (ValueError, ProviderConfigurationError, LLMError, MemoryStoreError)
        monkeypatch.setattr(svc, "_audit", AsyncMock())
        installed[kind].append(_judged_point(kind, name))
        entry = f"{kind}:{name}"
        # An LLM plugin names its role models in its own block, stored already.
        block = (
            {f"llm.{name}.expert_model": "acme-xl", f"llm.{name}.judge_model": "acme-xs"}
            if kind == "llm"
            else {}
        )
        agents: dict[str, Any] = {}
        if kind == "static":
            agents = {
                "checker": {
                    "role": "generic",
                    "label": "Checker",
                    "prompt": "p",
                    "static_provider": name,
                }
            }
        for allowed, accepted in (([entry], True), ([], False)):
            # The API process as each case says: the plugin loaded in it, or not.
            withdraw_every_plugin()
            if loaded:
                allow(entry)
            changes: dict[str, Any] = {"core.plugins.allowed": allowed, f"core.{selector}": name}
            if agents:
                changes[AGENT_DEFINITIONS_KEY] = agents
            api_said = ""
            try:
                await svc.SettingsService(_db({f"core.{k}": v for k, v in block.items()})).save(
                    changes, user_id=uuid.uuid4(), ip=None
                )
            except svc.SettingsValidationError as refused:
                api_said = str(refused)
            overrides: dict[str, Any] = {**block, "plugins.allowed": allowed, selector: name}
            if agents:
                overrides["agents.definitions"] = agents
            # From the stored settings alone, and with the job naming it too.
            for job_config in [None, *([{option: name}] if option else [])]:
                take_the_job_plugin_set(overrides)
                worker_said = ""
                try:
                    built = build_job_settings(overrides, job_config)
                    made = _what_the_worker_builds(kind, built)
                except worker_refusals as refused:
                    worker_said = f"{type(refused).__name__}: {refused}"
                else:
                    if kind == "llm":
                        # Read from the plugin's own block, with its model.
                        assert made.model == "acme-xl"
                assert (api_said == "", worker_said == "") == (accepted, accepted), (
                    allowed,
                    job_config,
                    api_said,
                    worker_said,
                )
            if not accepted:
                assert entry in api_said, api_said


class TestTheApiLoadsAPluginOnlyToRunItsCode:
    def test_judging_listing_and_choices_import_nothing(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        from app.services.settings_catalog_api import resolved_catalog

        points = {kind: _point(name, provides) for _key, kind, name, provides in KINDS}
        for kind, point in points.items():
            installed[kind].append(point)
        allowed = [f"{kind}:{point.name}" for kind, point in points.items()]
        for key, _kind, name, _provides in KINDS:
            _service().check_keys({key: name}, {"core.plugins.allowed": allowed})
        plugins.listing(allowed)
        served = {
            e.key: e.choices
            for e in resolved_catalog(["ghidra"], plugins_allowed=allowed)
            if e.key in {key for key, *_ in KINDS}
        }
        for key, _kind, name, _provides in KINDS:
            assert name in served[key], key
        assert [point.loads for point in points.values()] == [0, 0, 0, 0]

    def test_an_agent_s_test_loads_what_that_agent_runs_on(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        entries = [
            ("llm", "acme_llm"),
            ("llm", "other_llm"),
            ("static", "acme_static"),
            ("static", "other_static"),
            ("memory", "acme_memory"),
        ]
        for kind, name in entries:
            installed[kind].append(_point(name, AcmeStatic))
        allowed = [f"{kind}:{name}" for kind, name in entries]
        core = {
            "llm.provider": "acme_llm",
            "memory.backend": "acme_memory",
            "agents.definitions": {
                "checker": {"static_provider": "acme_static"},
                "other": {"static_provider": "other_static"},
            },
            "llm.agents": {"other": {"provider": "other_llm"}},
        }
        kinds = ("llm", "static", "sandbox")
        assert api_plugins.selected_plugins(core, allowed, kinds, "checker") == [
            "llm:acme_llm",
            "static:acme_static",
        ]
        assert api_plugins.selected_plugins(core, allowed, kinds, "other") == [
            "llm:acme_llm",
            "static:other_static",
            "llm:other_llm",
        ]
        # Selected but not on the stored list: nothing.
        assert api_plugins.selected_plugins(core, [], kinds, "checker") == []

    @pytest.mark.asyncio
    async def test_a_written_block_loads_its_plugin_alone(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        imported: list[str] = []
        point = FakePoint("acme_llm", llm_with_block("acme_llm"))
        installed["llm"].append(point)
        installed["memory"].append(ends_the_process("memory", "ending_memory", imported))
        installed["static"].append(ends_the_process("static", "ending_static", imported))
        allowed = ["llm:acme_llm", "memory:ending_memory", "static:ending_static"]
        # The allow-list, a provider id, a shipped provider's block: nothing.
        nothing = {
            "core.plugins.allowed": allowed,
            "core.static.provider": "ending_static",
            "core.memory.backend": "ending_memory",
            "core.llm.openai.expert_model": "gpt-4o",
        }
        assert api_plugins.block_writes(nothing, allowed) == []
        assert await api_plugins.load_written_blocks(nothing, allowed) is True
        assert point.loads == 0
        # A key of the plugin's own block: that plugin, and only once.
        written = {"core.llm.acme_llm.expert_model": "acme-xl"}
        assert await api_plugins.load_written_blocks(written, allowed) is True
        assert await api_plugins.load_written_blocks(written, allowed) is True
        assert point.loads == 1
        assert imported == []
        # Not named by the stored list: nothing.
        assert api_plugins.block_writes(written, []) == []

    @pytest.mark.asyncio
    async def test_a_plugin_that_hangs_holds_its_thread_and_no_request(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        release = threading.Event()
        installed["memory"].append(
            FakePoint("hanging", memory_plugin("hanging"), on_import=lambda: release.wait(30))
        )
        allowed = ["memory:hanging"]
        try:
            assert await api_plugins.load_in_background(allowed, allowed, 0.2) is False
            # Once the load has outlived a request's budget, the next request
            # does not wait on it, and no second load starts behind it.
            await asyncio.sleep(0.25)
            first = api_plugins._INFLIGHT[0]
            loop = asyncio.get_running_loop()
            began = loop.time()
            assert await api_plugins.load_in_background(allowed, allowed, 0.2) is False
            assert loop.time() - began < 0.2
            assert api_plugins._INFLIGHT[0] is first
            # Listing and judging go on meanwhile.
            assert plugins.accepted_names("memory", allowed) == {"hanging"}
            assert plugins.listing(allowed)[3]["plugins"][0]["state"] == "allowed"
        finally:
            release.set()
        held = api_plugins._INFLIGHT[0]
        assert held is not None
        await asyncio.wrap_future(held[0])
        assert plugins.records("memory")["hanging"].state == "loaded"


# (kind, the setting that selects it, a shipped id to select instead, its stored block)
ENDING = [
    ("llm", "core.llm.provider", "openai", {"expert_model": "k-expert", "judge_model": "k-judge"}),
    ("static", "core.static.provider", "ghidra", {}),
    ("sandbox", "core.sandbox.provider", "mock", {}),
    ("memory", "core.memory.backend", "memory", {"url": "http://ending.local:6333"}),
]


def _ending_rows(kind: str, selector: str | None, block: dict[str, Any]) -> dict[str, Any]:
    """The store allowing plugin ``ending_<kind>``, with its block, selected by ``selector``."""
    name = f"ending_{kind}"
    rows: dict[str, Any] = {"core.plugins.allowed": [f"{kind}:{name}"]}
    rows.update({f"core.{kind}.{name}.{leaf}": value for leaf, value in block.items()})
    if selector is not None:
        rows[selector] = name
    return rows


def _quiet_save() -> Any:
    """What a save answers besides itself, left out: the advisory notes and the audit write."""
    from contextlib import ExitStack

    stack = ExitStack()
    for target in ("_agent_warnings", "_mapping_warnings"):
        stack.enter_context(patch(f"app.api.v1.settings.{target}", AsyncMock(return_value={})))
    stack.enter_context(patch("app.api.v1.settings.audit_record", AsyncMock()))
    stack.enter_context(patch.object(svc, "_audit", AsyncMock()))
    return stack


@pytest.mark.parametrize(("kind", "selector", "shipped", "block"), ENDING)
class TestAPluginWhoseImportEndsTheProcessCanBeRemoved:
    def test_the_settings_pages_serve_it_unimported(
        self,
        installed: dict[str, list[FakePoint]],
        kind: str,
        selector: str,
        shipped: str,
        block: dict[str, Any],
    ) -> None:
        imported: list[str] = []
        name = f"ending_{kind}"
        installed[kind].append(ends_the_process(kind, name, imported))
        rows = _ending_rows(kind, selector, block)
        # A credential of its block is stored as a secret row, never shown.
        hidden = f"core.{kind}.{name}.api_key"
        if block:
            rows[hidden] = "stored-ciphertext"
        client = TestClient(_app(db=_db(rows, secret=frozenset({hidden}))))
        answers = [
            client.get(path)
            for path in (
                "/api/v1/settings/schema",
                "/api/v1/settings",
                "/api/v1/settings/export",
                "/api/v1/settings/plugins",
            )
        ]
        assert [answer.status_code for answer in answers] == [200, 200, 200, 200]
        schema, values, exported, _listed = (answer.json() for answer in answers)
        served = {e["key"]: e for group in schema["groups"] for e in group["entries"]}
        for leaf, value in block.items():
            key = f"core.{kind}.{name}.{leaf}"
            assert served[key]["subgroup"] == f"{kind}:{name} (as stored)"
            assert values["values"][key]["value"] == value
            assert exported["values"][key] == value
        if block:
            assert (served[hidden]["type"], served[hidden]["secret"]) == ("secret", True)
            assert values["values"][hidden]["value"] is None
            assert values["values"][hidden]["is_set"] is True
            assert hidden not in exported["values"]
            assert hidden in exported["secrets_omitted"]
        assert imported == []

    def test_a_save_removes_it_with_the_settings_that_select_it(
        self,
        installed: dict[str, list[FakePoint]],
        kind: str,
        selector: str,
        shipped: str,
        block: dict[str, Any],
    ) -> None:
        imported: list[str] = []
        installed[kind].append(ends_the_process(kind, f"ending_{kind}", imported))
        rows = _ending_rows(kind, selector, block)
        with _quiet_save():
            held = _db(rows)
            refused = TestClient(_app(db=held)).patch(
                "/api/v1/settings", json={"changes": {"core.plugins.allowed": []}}
            )
            assert refused.status_code == 422
            assert selector in refused.json()["errors"]
            held.commit.assert_not_awaited()
            held = _db(rows)
            removed = TestClient(_app(db=held)).patch(
                "/api/v1/settings",
                json={"changes": {"core.plugins.allowed": [], selector: shipped}},
            )
        assert removed.status_code == 200, removed.text
        assert sorted(removed.json()["applied"]) == sorted(["core.plugins.allowed", selector])
        held.commit.assert_awaited_once()
        assert imported == []

    def test_a_reset_of_its_group_or_of_the_list_removes_it(
        self,
        installed: dict[str, list[FakePoint]],
        kind: str,
        selector: str,
        shipped: str,
        block: dict[str, Any],
    ) -> None:
        imported: list[str] = []
        installed[kind].append(ends_the_process(kind, f"ending_{kind}", imported))
        with _quiet_save():
            held = _db(_ending_rows(kind, selector, block))
            refused = TestClient(_app(db=held)).delete(
                "/api/v1/settings", params={"group": "plugins"}
            )
            assert refused.status_code == 422
            assert selector in refused.json()["errors"]
            held.delete.assert_not_awaited()
            answers = [
                TestClient(_app(db=_db(_ending_rows(kind, None, block)))).delete(
                    path, params=params
                )
                for path, params in (
                    ("/api/v1/settings", {"group": "plugins"}),
                    ("/api/v1/settings/core.plugins.allowed", {}),
                )
            ]
        for answer in answers:
            assert answer.status_code == 200, answer.text
            assert answer.json()["reset"] == ["core.plugins.allowed"]
        assert imported == []

    def test_an_import_removes_it(
        self,
        installed: dict[str, list[FakePoint]],
        kind: str,
        selector: str,
        shipped: str,
        block: dict[str, Any],
    ) -> None:
        imported: list[str] = []
        installed[kind].append(ends_the_process(kind, f"ending_{kind}", imported))
        held = _db(_ending_rows(kind, selector, block))
        with _quiet_save():
            answer = TestClient(_app(db=held)).post(
                "/api/v1/settings/import",
                json={
                    "format": "maljan-settings/2",
                    "values": {"core.plugins.allowed": [], selector: shipped},
                },
            )
        assert answer.status_code == 200, answer.text
        held.commit.assert_awaited_once()
        assert imported == []

    def test_an_export_edited_to_drop_it_imports_back_and_removes_it(
        self,
        installed: dict[str, list[FakePoint]],
        kind: str,
        selector: str,
        shipped: str,
        block: dict[str, Any],
    ) -> None:
        imported: list[str] = []
        name = f"ending_{kind}"
        installed[kind].append(ends_the_process(kind, name, imported))
        rows = _ending_rows(kind, selector, block)
        exported = TestClient(_app(db=_db(rows))).get("/api/v1/settings/export").json()
        own = {f"core.{kind}.{name}.{leaf}" for leaf in block}
        # The export carries its block as stored; the file is edited to drop it.
        assert own <= set(exported["values"])
        document = {**exported["values"], "core.plugins.allowed": [], selector: shipped}
        held = _db(rows)
        with _quiet_save():
            answer = TestClient(_app(db=held)).post(
                "/api/v1/settings/import",
                json={"format": exported["format"], "values": document},
            )
        assert answer.status_code == 200, answer.text
        body = answer.json()
        # Its block, sent back as stored, is no write: left out, quietly.
        assert sorted(body["applied"]) == sorted(["core.plugins.allowed", selector])
        assert not own & set(body["warnings"])
        held.commit.assert_awaited_once()
        removed = {call.args[0].key for call in held.delete.await_args_list}
        assert not removed & own
        assert imported == []

    def test_an_unedited_export_imports_back_without_importing_it(
        self,
        installed: dict[str, list[FakePoint]],
        kind: str,
        selector: str,
        shipped: str,
        block: dict[str, Any],
    ) -> None:
        imported: list[str] = []
        name = f"ending_{kind}"
        installed[kind].append(ends_the_process(kind, name, imported))
        rows = _ending_rows(kind, selector, block)
        exported = TestClient(_app(db=_db(rows))).get("/api/v1/settings/export").json()
        # Allowed and selected, and imported back exactly as exported.
        assert exported["values"]["core.plugins.allowed"] == [f"{kind}:{name}"]
        assert exported["values"][selector] == name
        held = _db(rows)
        with _quiet_save():
            answer = TestClient(_app(db=held)).post(
                "/api/v1/settings/import",
                json={"format": exported["format"], "values": exported["values"]},
            )
        assert answer.status_code == 200, answer.text
        own = {f"core.{kind}.{name}.{leaf}" for leaf in block}
        assert not own & set(answer.json()["applied"])
        assert imported == []


# The kinds whose plugins keep a settings block of their own.
WITH_A_BLOCK = [case for case in ENDING if case[3]]


@pytest.mark.parametrize(("kind", "selector", "shipped", "block"), WITH_A_BLOCK)
class TestABlockSentBackAsStoredWritesNothing:
    def test_a_save_of_its_stored_values_loads_nothing_and_writes_nothing(
        self,
        installed: dict[str, list[FakePoint]],
        kind: str,
        selector: str,
        shipped: str,
        block: dict[str, Any],
    ) -> None:
        imported: list[str] = []
        name = f"ending_{kind}"
        installed[kind].append(ends_the_process(kind, name, imported))
        rows = _ending_rows(kind, selector, block)
        held_rows = _triples(rows)
        own = {f"core.{kind}.{name}.{leaf}": value for leaf, value in block.items()}
        assert api_plugins.unchanged_block_keys(own, held_rows) == set(own)
        dropping = {**own, "core.plugins.allowed": []}
        assert api_plugins.unchanged_block_keys(dropping, held_rows) == set(own)
        changed = {key: "changed" for key in own}
        assert api_plugins.unchanged_block_keys(changed, held_rows) == set()
        held = _db(rows)
        with _quiet_save():
            answer = TestClient(_app(db=held)).patch("/api/v1/settings", json={"changes": own})
        assert answer.status_code == 200, answer.text
        assert answer.json()["applied"] == []
        held.add.assert_not_called()
        assert imported == []

    def test_a_clear_of_a_block_key_deletes_its_row_and_loads_nothing(
        self,
        installed: dict[str, list[FakePoint]],
        kind: str,
        selector: str,
        shipped: str,
        block: dict[str, Any],
    ) -> None:
        imported: list[str] = []
        name = f"ending_{kind}"
        installed[kind].append(ends_the_process(kind, name, imported))
        # Allowed and selected, with a credential stored as a secret row.
        secret = f"core.{kind}.{name}.api_key"
        plain = f"core.{kind}.{name}.{next(iter(block))}"
        rows = {**_ending_rows(kind, selector, block), secret: "stored-ciphertext"}
        assert api_plugins.block_writes({secret: None}, rows["core.plugins.allowed"]) == []
        answers = []
        with _quiet_save():
            for key, send in (
                (secret, lambda c, k: c.patch("/api/v1/settings", json={"changes": {k: None}})),
                (plain, lambda c, k: c.patch("/api/v1/settings", json={"changes": {k: None}})),
                (
                    secret,
                    lambda c, k: c.post(
                        "/api/v1/settings/import",
                        json={"format": "maljan-settings/2", "values": {k: None}},
                    ),
                ),
            ):
                held = _db(rows, secret=frozenset({secret}))
                answer = send(TestClient(_app(db=held)), key)
                answers.append((key, answer.status_code, answer.json().get("applied")))
                (deleted,) = [call.args[0].key for call in held.delete.await_args_list]
                assert deleted == key
                held.add.assert_not_called()
        assert answers == [(secret, 200, [secret]), (plain, 200, [plain]), (secret, 200, [secret])]
        assert imported == []


def _triples(rows: dict[str, Any], secret: frozenset[str] = frozenset()) -> list[Any]:
    """``rows`` as the store holds them: ``(key, value, is_secret)``."""
    return [(key, value, key in secret) for key, value in rows.items()]


class TestABlockValueIsComparedExactly:
    def test_as_canonical_json_and_never_against_a_secret(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        installed["llm"].append(FakePoint("acme_llm", llm_with_block("acme_llm")))
        prefix = "core.llm.acme_llm."
        rows = _triples(
            {
                f"{prefix}retries": 1,
                f"{prefix}extra": {"a": 1, "b": [1, 2]},
                f"{prefix}api_key": "the-stored-value",
            },
            secret=frozenset({f"{prefix}api_key"}),
        )

        def unchanged(key: str, value: Any) -> bool:
            return api_plugins.unchanged_block_keys({prefix + key: value}, rows) == {prefix + key}

        assert unchanged("retries", 1)
        assert not unchanged("retries", True)
        assert not unchanged("retries", 1.0)
        assert not unchanged("retries", float("nan"))
        assert unchanged("extra", {"b": [1, 2], "a": 1})
        assert not unchanged("extra", {"a": True, "b": [1.0, 2]})
        assert not unchanged("extra", {"a": 1, "b": [2, 1]})
        # A secret sent is always a write, whatever it holds.
        assert not unchanged("api_key", "the-stored-value")


class TestAStoredSecretAnswersNoGuess:
    @pytest.mark.parametrize("allowed", [[], ["llm:acme_llm"]])
    def test_a_right_and_a_wrong_guess_get_the_same_answer(
        self, installed: dict[str, list[FakePoint]], allowed: list[str]
    ) -> None:
        # Installed but never loaded here: not allowed, or allowed and failing to
        # import. Its block holds a credential the store can decrypt.
        installed["llm"].append(FakePoint("acme_llm", ImportError("no client")))
        key = "core.llm.acme_llm.api_key"
        rows = {"core.plugins.allowed": allowed, key: "stored-ciphertext"}
        requests = (
            ("patch", "/api/v1/settings", lambda guess: {"changes": {key: guess, "core.no": 1}}),
            (
                "post",
                "/api/v1/settings/import",
                lambda guess: {"format": "maljan-settings/2", "values": {key: guess}},
            ),
        )
        answers: dict[str, list[Any]] = {}
        with _quiet_save(), patch("maljan.core.settings_secrets.decrypt", lambda _v: "right-guess"):
            for guess in ("right-guess", "wrong-guess"):
                said = []
                for method, path, body in requests:
                    held = _db(rows, secret=frozenset({key}))
                    client = TestClient(_app(db=held))
                    answer = getattr(client, method)(path, json=body(guess))
                    said.append((answer.status_code, answer.json()))
                    held.commit.assert_not_awaited()
                answers[guess] = said
        assert answers["right-guess"] == answers["wrong-guess"]
        assert [status for status, _body in answers["right-guess"]] == [422, 422]


@pytest.mark.parametrize(("kind", "selector", "shipped", "block"), WITH_A_BLOCK)
class TestAChangeThatDropsAPluginNeverLoadsIt:
    def test_a_changed_block_beside_the_drop_is_refused_naming_the_drop(
        self,
        installed: dict[str, list[FakePoint]],
        kind: str,
        selector: str,
        shipped: str,
        block: dict[str, Any],
    ) -> None:
        imported: list[str] = []
        name = f"ending_{kind}"
        installed[kind].append(ends_the_process(kind, name, imported))
        rows = _ending_rows(kind, selector, block)
        leaf = next(iter(block))
        key = f"core.{kind}.{name}.{leaf}"
        change = {"core.plugins.allowed": [], selector: shipped, key: "changed"}
        assert api_plugins.block_writes(change, rows["core.plugins.allowed"]) == []
        answers = []
        with _quiet_save():
            for held, call in (
                (_db(rows), lambda c: c.patch("/api/v1/settings", json={"changes": change})),
                (
                    _db(rows),
                    lambda c: c.post(
                        "/api/v1/settings/import",
                        json={"format": "maljan-settings/2", "values": change},
                    ),
                ),
            ):
                answers.append(call(TestClient(_app(db=held))))
                held.commit.assert_not_awaited()
        for answer in answers:
            assert answer.status_code == 422, answer.text
            said = answer.json()["errors"][key]
            assert "which this change drops from the plugin allow-list" in said
        assert imported == []


class TestASaveThatWritesAPluginBlock:
    def test_loads_that_plugin_alone_and_reads_the_key_with_its_model(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        imported: list[str] = []
        point = FakePoint("acme_llm", llm_with_block("acme_llm"))
        installed["llm"].append(point)
        installed["memory"].append(ends_the_process("memory", "ending_memory", imported))
        installed["static"].append(ends_the_process("static", "ending_static", imported))
        allowed = ["llm:acme_llm", "memory:ending_memory", "static:ending_static"]
        held = _db({"core.plugins.allowed": allowed})
        with _quiet_save():
            answer = TestClient(_app(db=held)).patch(
                "/api/v1/settings", json={"changes": {"core.llm.acme_llm.expert_model": "acme-xl"}}
            )
        assert answer.status_code == 200, answer.text
        assert answer.json()["applied"] == ["core.llm.acme_llm.expert_model"]
        held.commit.assert_awaited_once()
        assert point.loads == 1
        assert imported == []

    def test_one_the_stored_list_does_not_name_is_refused_with_the_order_to_save_in(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        point = FakePoint("acme_llm", llm_with_block("acme_llm"))
        installed["llm"].append(point)
        held = _db({})
        with _quiet_save():
            answer = TestClient(_app(db=held)).patch(
                "/api/v1/settings",
                json={
                    "changes": {
                        "core.plugins.allowed": ["llm:acme_llm"],
                        "core.llm.acme_llm.expert_model": "acme-xl",
                    }
                },
            )
        assert answer.status_code == 422
        said = answer.json()["errors"]["core.llm.acme_llm.expert_model"]
        assert "save the list naming llm:acme_llm first, then its settings" in said
        held.commit.assert_not_awaited()
        assert point.loads == 0


class TestARunningJobKeepsItsPlugins:
    def test_a_list_saved_while_the_job_runs_applies_to_the_next_job(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        from app.worker.analysis_worker import build_job_settings, take_the_job_plugin_set
        from maljan.llm.provider_base import facts_of
        from maljan.llm.registry import _PROVIDER_REGISTRY, LLMProviderRegistry

        installed["llm"].append(FakePoint("acme_llm", AcmeLLM))
        installed["static"].append(FakePoint("acme_static", AcmeStatic))
        started = {
            "plugins.allowed": ["llm:acme_llm", "static:acme_static"],
            "static.provider": "acme_static",
        }
        take_the_job_plugin_set(started)
        built = build_job_settings(started, {})
        # A save drops both plugins and the job reads the store again (a
        # runtime setting, an enrichment): nothing is withdrawn under it.
        plugins.install_allow_list([])
        asyncio.run(svc.SettingsService(_db({"core.plugins.allowed": []})).load_overrides())
        LLMProviderRegistry(built)
        assert _PROVIDER_REGISTRY.get("acme_llm") is AcmeLLM
        assert facts_of("acme_llm") is AcmeLLM
        assert isinstance(registry.get_static_provider(built), AcmeStatic)
        # The next job starts with the list as saved.
        take_the_job_plugin_set({"plugins.allowed": []})
        assert "acme_llm" not in _PROVIDER_REGISTRY
        assert "acme_static" not in registry.static_provider_ids()


class TestTheCommandLine:
    def test_analyze_judges_its_provider_as_a_save_does(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from maljan import cli

        built: list[str] = []

        class _Stop:
            def __init__(self, config: Any, mock: bool, **_options: Any) -> None:
                built.append(str(config.llm.provider))
                raise RuntimeError("stopped before running")

        monkeypatch.setattr(cli, "Settings", lambda: Settings(_env_file=None))
        monkeypatch.setattr(cli, "MaljanApp", _Stop)
        refused = CliRunner().invoke(cli.app, ["analyze", "abc", "--provider", "bogus"])
        assert refused.exit_code == 2
        assert "provider must be one of" in refused.output
        assert built == []
        shipped = CliRunner().invoke(cli.app, ["analyze", "abc", "--provider", "anthropic"])
        assert shipped.exit_code == 1
        assert built == ["anthropic"]

    def test_analyze_with_an_llm_plugin_runs_on_its_block_s_models(
        self, installed: dict[str, list[FakePoint]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from maljan import cli

        installed["llm"].append(FakePoint("acme_llm", llm_with_block("acme_llm")))
        seen: list[tuple[str, str, str]] = []

        class _Stop:
            def __init__(self, config: Any, mock: bool, **_options: Any) -> None:
                llm = config.llm
                seen.append((str(llm.provider), llm.expert_model, llm.judge_model))
                raise RuntimeError("stopped before running")

        monkeypatch.setattr(
            cli,
            "Settings",
            lambda: Settings(
                _env_file=None,
                plugins={"allowed": ["llm:acme_llm"]},
                llm={"acme_llm": {"expert_model": "acme-xl", "judge_model": "acme-xs"}},
            ),
        )
        monkeypatch.setattr(cli, "MaljanApp", _Stop)
        ran = CliRunner().invoke(cli.app, ["analyze", "abc", "--provider", "acme_llm"])
        assert ran.exit_code == 1, ran.output
        assert seen == [("acme_llm", "acme-xl", "acme-xs")]


def test_an_unloaded_plugins_stored_block_is_served_masked(
    installed: dict[str, list[FakePoint]],
) -> None:
    """A plugin block the API has not loaded is served as stored, masked as the export
    masks it: a URL's password, and a value under a key that names a credential."""
    imported: list[str] = []
    kind, name = "memory", "ending_memory"
    installed[kind].append(ends_the_process(kind, name, imported))
    secret_url = "http://user:f10plugpw@ending.local:6333"
    rows = _ending_rows(
        kind,
        "core.memory.backend",
        {"url": secret_url, "extra": {"api_token": "f10plugtok", "mode": "fast"}, "token": "x9"},
    )
    client = TestClient(_app(db=_db(rows)))
    values = client.get("/api/v1/settings")
    exported = client.get("/api/v1/settings/export")
    assert values.status_code == 200 and exported.status_code == 200
    assert "f10plug" not in values.text and "f10plug" not in exported.text
    served = values.json()["values"]
    mask = "**********"
    assert served[f"core.{kind}.{name}.url"]["value"] == f"http://{mask}@ending.local:6333"
    assert served[f"core.{kind}.{name}.extra"]["value"] == {"api_token": mask, "mode": "fast"}
    assert served[f"core.{kind}.{name}.token"]["value"] == mask
    assert exported.json()["values"][f"core.{kind}.{name}.extra"] == {
        "api_token": mask,
        "mode": "fast",
    }
    assert imported == []
