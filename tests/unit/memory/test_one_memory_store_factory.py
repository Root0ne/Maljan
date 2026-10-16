"""One factory builds the configured memory store for every caller.

Two backends throughout: the in-process store, and Qdrant through its own
client against a fake server. The enrichment worker, the API's purge dry run,
``/health``, the function-hash steps and the command line each get the store
``memory.backend`` selects, and none of them names a backend: a third backend
registered at run time is used by the same callers unchanged.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pydantic import BaseModel, SecretStr

from maljan.core import plugins
from maljan.core.config import Settings
from maljan.core.exceptions import MemoryStoreError
from maljan.memory import store_factory
from maljan.memory.function_hash_store import FunctionHashStore, FunctionMatch
from maljan.memory.in_memory_store import InMemoryStore
from maljan.memory.long_term_memory import MemoryStore, StoredCase
from maljan.memory.qdrant_store import QdrantStore

URL = "http://qdrant.internal:6333"


class _FakeQdrant:
    """The slice of ``QdrantClient`` the stores call, held in memory."""

    built: list[_FakeQdrant] = []
    down = False
    seed: dict[str, dict[int, dict[str, Any]]] = {}

    def __init__(self, url: str = "", api_key: str | None = None) -> None:
        self.url = url
        self.api_key = api_key
        self.collections: dict[str, dict[int, dict[str, Any]]] = {
            name: dict(points) for name, points in self.seed.items()
        }
        self.scroll_calls = 0
        self.deleted: list[Any] = []
        self.closed = 0
        _FakeQdrant.built.append(self)

    def close(self) -> None:
        self.closed += 1

    def get_collections(self) -> Any:
        if self.down:
            raise ConnectionError(f"connection refused by {self.url}")
        return SimpleNamespace(collections=[SimpleNamespace(name=n) for n in self.collections])

    def get_collection(self, name: str) -> Any:
        return SimpleNamespace(points_count=len(self.collections[name]), config=None)

    def create_collection(self, collection_name: str, **_kwargs: Any) -> None:
        self.collections.setdefault(collection_name, {})

    def create_payload_index(self, **_kwargs: Any) -> None:
        return None

    def upsert(self, collection_name: str, points: list[Any], wait: bool = True) -> None:
        if self.closed:
            raise RuntimeError("the client is closed")
        for point in points:
            self.collections[collection_name][point.id] = dict(point.payload)

    def scroll(
        self,
        collection_name: str,
        limit: int,
        offset: Any = None,
        with_payload: bool = True,
        with_vectors: bool = False,
        scroll_filter: Any = None,
    ) -> tuple[list[Any], Any]:
        self.scroll_calls += 1
        points = sorted(self.collections[collection_name].items())
        if scroll_filter is not None:
            wanted = set(scroll_filter.must[0].match.any)
            points = [(i, p) for i, p in points if p.get("func_hash") in wanted]
        start = int(offset or 0)
        page = points[start : start + limit]
        following = start + limit if start + limit < len(points) else None
        return [SimpleNamespace(id=i, payload=p) for i, p in page], following

    def delete(self, collection_name: str, points_selector: Any, wait: bool = True) -> None:
        for point_id in points_selector.points:
            self.collections[collection_name].pop(point_id, None)
            self.deleted.append(point_id)


@pytest.fixture(autouse=True)
def _fake_qdrant(monkeypatch: pytest.MonkeyPatch) -> Iterator[type[_FakeQdrant]]:
    _FakeQdrant.built = []
    _FakeQdrant.down = False
    _FakeQdrant.seed = {}
    monkeypatch.setattr("qdrant_client.QdrantClient", _FakeQdrant)
    # This process's plugin state, fresh: no plugin allowed, none tried.
    monkeypatch.setattr(plugins, "_STATE", plugins._ProcessState())
    store_factory.forget_built_stores()
    yield _FakeQdrant
    store_factory.forget_built_stores()


def _installed(monkeypatch: pytest.MonkeyPatch, *points: Any) -> None:
    """``points`` are the installed memory plugins' entry points, as package metadata lists them."""
    monkeypatch.setattr(
        plugins,
        "_entry_points",
        lambda group: list(points) if group == store_factory.ENTRY_POINT_GROUP else [],
    )


class _ThirdSettings(BaseModel):
    endpoint: str = "http://store:9000"
    token: SecretStr | None = None


@pytest.fixture
def third_backend() -> Any:
    """A backend none of the callers was written for, removed again afterwards."""

    class _Hashes:
        def __init__(self) -> None:
            self.rows: list[FunctionMatch] = []

        def upsert_sample(self, sample_id: str, family: str, functions: list[Any]) -> int:
            self.rows += [FunctionMatch(h, family, sample_id, n) for h, n in functions]
            return len(functions)

        def match(self, hashes: list[str], exclude_sample_id: str | None = None) -> list[Any]:
            return [
                r for r in self.rows if r.func_hash in hashes and r.sample_id != exclude_sample_id
            ]

        def count(self) -> int:
            return len(self.rows)

    hashes = _Hashes()
    hashes.upsert_sample("older", "FamilyA", [("h1", "f1"), ("h2", "f2")])

    class _Third(InMemoryStore):
        def __init__(self, endpoint: str) -> None:
            super().__init__()
            self.endpoint = endpoint

        def readiness(self) -> str:
            return f"third backend ready at {self.endpoint}"

        def function_hash_store(self) -> Any:
            return hashes

    def _build(memory: Any) -> _Third:
        return _Third(store_factory.backend_settings(memory, "third").endpoint)

    store_factory.register_memory_backend(
        "third",
        _build,
        settings_model=_ThirdSettings,
        annotations={"endpoint": {"title": "Third endpoint", "description": "Where it is."}},
    )
    yield Settings(
        _env_file=None, memory={"backend": "third", "third": {"endpoint": "http://third:1"}}
    )
    store_factory._BACKENDS.pop("third", None)
    store_factory.forget_built_stores()


def _settings(backend: str) -> Settings:
    return Settings(
        _env_file=None,
        memory={"backend": backend, "qdrant": {"url": URL, "api_key": "k"}},
    )


def _case(sample_id: str, total: int, corroborated: int = 0, errors: bool = False) -> StoredCase:
    return StoredCase(
        sample_id=sample_id,
        summary_text=sample_id,
        total_techniques=total,
        corroborated_count=corroborated,
        has_analyst_errors=errors,
    )


def _payload(case: StoredCase) -> dict[str, Any]:
    return {
        "sample_id": case.sample_id,
        "total_techniques": case.total_techniques,
        "corroborated_count": case.corroborated_count,
        "has_analyst_errors": case.has_analyst_errors,
    }


def _seed_cases(*cases: StoredCase) -> None:
    _FakeQdrant.seed = {"maljan_cases_v2": {i: _payload(c) for i, c in enumerate(cases)}}


def _in_process_with(*cases: StoredCase) -> InMemoryStore:
    store = InMemoryStore()
    store._cases = [(c, [0.0]) for c in cases]
    return store


THIN, RICH, FAILED = _case("thin", 0), _case("rich", 3, 2), _case("failed", 5, 3, errors=True)


class TestTheFactoryBuildsTheConfiguredStore:
    def test_the_in_process_backend_dials_nothing(self) -> None:
        store = store_factory.build_memory_store(_settings("memory"))
        assert isinstance(store, InMemoryStore)
        assert isinstance(store, MemoryStore)
        assert _FakeQdrant.built == []

    def test_the_qdrant_backend_gets_its_settings_through_its_client(self) -> None:
        store = store_factory.build_memory_store(_settings("qdrant"))
        assert isinstance(store, QdrantStore)
        assert isinstance(store, MemoryStore)
        (client,) = _FakeQdrant.built
        assert (client.url, client.api_key) == (URL, "k")

    def test_the_memory_block_alone_is_enough(self) -> None:
        assert isinstance(
            store_factory.build_memory_store(_settings("memory").memory), InMemoryStore
        )

    def test_an_unregistered_backend_is_not_configured(self) -> None:
        with pytest.raises(store_factory.MemoryBackendNotConfiguredError, match="known: memory"):
            store_factory.build_memory_store(SimpleNamespace(backend="nothing"))

    def test_a_registered_backend_is_built_like_the_shipped_ones(self, third_backend: Any) -> None:
        assert "third" in store_factory.memory_backends()
        store = store_factory.build_memory_store(third_backend)
        assert store.readiness() == "third backend ready at http://third:1"

    def test_an_empty_id_cannot_be_registered(self) -> None:
        with pytest.raises(ValueError):
            store_factory.register_memory_backend(" ", lambda _m: InMemoryStore())


class TestTheDryRunPurgeCountsWithoutDeleting:
    def test_in_process(self) -> None:
        store = _in_process_with(THIN, RICH, FAILED)
        assert store.purge_low_quality(dry_run=True) == 2
        assert store.count() == 3
        assert store.purge_low_quality() == 2
        assert store.count() == 1

    def test_qdrant(self) -> None:
        _seed_cases(THIN, RICH, FAILED)
        store = store_factory.build_memory_store(_settings("qdrant"))
        (client,) = _FakeQdrant.built
        assert store.purge_low_quality(dry_run=True) == 2
        assert client.deleted == [] and store.count() == 3
        assert store.purge_low_quality() == 2
        assert store.count() == 1

    def test_the_qdrant_walk_grows_with_the_collection_and_no_faster(self) -> None:
        """Pages, not points: ten times the cases is about ten times the scrolls."""

        def scrolls(n: int) -> int:
            _seed_cases(*(_case(f"s{i}", i % 3) for i in range(n)))
            store = store_factory.build_memory_store(_settings("qdrant"))
            store.purge_low_quality(dry_run=True)
            return _FakeQdrant.built[-1].scroll_calls

        small, large = scrolls(512), scrolls(5120)
        assert large <= 10 * small + 1


class TestReadiness:
    def test_in_process_answers_without_io(self) -> None:
        assert store_factory.build_memory_store(_settings("memory")).readiness() == "in process"

    def test_qdrant_answers_from_its_server(self) -> None:
        answer = store_factory.build_memory_store(_settings("qdrant")).readiness()
        assert "maljan_cases_v2" in answer

    def test_an_unreachable_qdrant_raises_a_memory_store_error_naming_no_password(self) -> None:
        _FakeQdrant.down = True
        cfg = Settings(
            _env_file=None,
            memory={"backend": "qdrant", "qdrant": {"url": "http://user:pw-123@q:6333"}},
        )
        with pytest.raises(MemoryStoreError) as raised:
            store_factory.build_memory_store(cfg).readiness()
        assert "pw-123" not in str(raised.value)


class TestTheFunctionHashStoreIsTheBackendsOwn:
    def test_the_in_process_backend_keeps_none(self) -> None:
        assert store_factory.build_function_hash_store(_settings("memory")) is None

    def test_qdrant_keeps_one_on_the_same_client(self) -> None:
        store = store_factory.build_function_hash_store(_settings("qdrant"))
        assert isinstance(store, FunctionHashStore)
        assert len(_FakeQdrant.built) == 1  # the case store's client, shared
        assert store.upsert_sample("older", "FamilyA", [("h1", "f1")]) == 1
        (match,) = store.match(["h1", "h9"], exclude_sample_id="this")
        assert (match.family, match.sample_id) == ("FamilyA", "older")


class TestTheEnrichWorkerReadsTheConfiguredBackend:
    @staticmethod
    def _built(settings: Any) -> Any:
        from app.worker import enrich_worker

        enrich_worker._memory_store_built = False
        enrich_worker._memory_store = None
        try:
            with patch(
                "app.worker.enrich_worker.runtime_config.core",
                AsyncMock(return_value=settings),
            ):
                return asyncio.run(enrich_worker._get_memory_store())
        finally:
            enrich_worker._memory_store_built = False
            enrich_worker._memory_store = None

    def test_the_in_process_backend_never_dials_qdrant(self) -> None:
        assert isinstance(self._built(_settings("memory")), InMemoryStore)
        assert _FakeQdrant.built == []

    def test_the_qdrant_backend(self) -> None:
        assert isinstance(self._built(_settings("qdrant")), QdrantStore)
        assert [c.url for c in _FakeQdrant.built] == [URL]

    def test_a_registered_backend(self, third_backend: Any) -> None:
        store = self._built(third_backend)
        assert store.readiness() == "third backend ready at http://third:1"


class TestThePurgeRouteAsksTheStore:
    @staticmethod
    def _purge(backend: str, dry_run: bool) -> dict[str, Any]:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.api.v1.system import router
        from app.database import get_db
        from app.deps import require_admin

        app = FastAPI()
        app.include_router(router, prefix="/api/v1")
        app.dependency_overrides[require_admin] = lambda: SimpleNamespace(id="admin")
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        overrides = {"memory.backend": backend, "memory.qdrant.url": URL}
        with patch(
            "app.services.settings_service.load_core_overrides",
            AsyncMock(return_value=overrides),
        ):
            response = TestClient(app).post("/api/v1/system/ltm/purge", json={"dry_run": dry_run})
        assert response.status_code == 200, response.text
        return response.json()

    def test_qdrant_dry_run_counts_and_deletes_nothing(self) -> None:
        _seed_cases(THIN, RICH, FAILED)
        body = self._purge("qdrant", dry_run=True)
        assert body == {"removed": 2, "backend": "QdrantStore", "dry_run": True}
        assert _FakeQdrant.built[-1].deleted == []

    def test_qdrant_purge_deletes(self) -> None:
        _seed_cases(THIN, RICH, FAILED)
        assert self._purge("qdrant", dry_run=False)["removed"] == 2
        assert len(_FakeQdrant.built[-1].deleted) == 2

    def test_the_in_process_dry_run_dials_nothing(self) -> None:
        body = self._purge("memory", dry_run=True)
        assert body == {"removed": 0, "backend": "InMemoryStore", "dry_run": True}
        assert _FakeQdrant.built == []


class TestHealthProbesTheConfiguredBackend:
    @staticmethod
    def _memory_component(settings: Any) -> dict[str, Any]:
        import app.main as main_mod
        from app.runtime_config import runtime_config

        async def _ok() -> None:
            return None

        # The stored plugin allow-list is the one the test put in force.
        stored = sorted(plugins.allow_list())
        with (
            patch.object(runtime_config, "core", AsyncMock(return_value=settings)),
            patch.object(runtime_config, "stored_value", AsyncMock(return_value=stored)),
            patch.object(main_mod, "_probe_database", _ok),
            patch.object(main_mod, "_probe_redis", _ok),
            patch.object(main_mod, "_probe_minio", _ok),
        ):
            components = asyncio.run(main_mod._probe_components())
        assert "qdrant" not in components
        return components["memory"]

    def test_the_in_process_backend_is_ready_without_qdrant(self) -> None:
        _FakeQdrant.down = True
        assert self._memory_component(_settings("memory")) == {
            "ok": True,
            "error": None,
            "backend": "memory",
        }
        assert _FakeQdrant.built == []

    def test_a_reachable_qdrant(self) -> None:
        component = self._memory_component(_settings("qdrant"))
        assert component["ok"] is True and component["backend"] == "qdrant"

    def test_an_unreachable_qdrant_is_a_failure(self) -> None:
        _FakeQdrant.down = True
        component = self._memory_component(_settings("qdrant"))
        assert component["ok"] is False
        assert "did not answer" in component["error"]

    def test_an_unregistered_backend_is_reported_not_configured(self) -> None:
        component = self._memory_component(SimpleNamespace(memory=SimpleNamespace(backend="x")))
        assert component == {"ok": None, "error": None, "backend": "x", "detail": "not configured"}

    def test_a_registered_backend_is_probed(self, third_backend: Any) -> None:
        component = self._memory_component(third_backend)
        assert component["ok"] is True and component["backend"] == "third"


class TestTheFunctionMatchStepUsesTheConfiguredBackend:
    @staticmethod
    def _step(config: Any) -> Any:
        from maljan.pipeline.nodes import _function_matches_step

        provider = SimpleNamespace(
            capabilities=SimpleNamespace(provides_function_hashes=True),
            function_hashes=lambda _job: [("f1", "h1"), ("f3", "h3")],
        )
        container = SimpleNamespace(config=config, get_static_provider=lambda: provider)
        state = {"static_sample_path": "/mirror/s.bin", "file_hash": "this"}
        return _function_matches_step(container, state)  # type: ignore[arg-type]

    def test_no_step_for_a_backend_without_function_hashes(self) -> None:
        assert self._step(_settings("memory")) is None
        assert _FakeQdrant.built == []

    def test_qdrant_answers_from_its_function_hash_collection(self) -> None:
        _FakeQdrant.seed = {
            "maljan_function_hashes_v1": {
                1: {"func_hash": "h1", "family": "FamilyA", "sample_id": "older", "func_name": "f1"}
            }
        }
        args, value = self._step(_settings("qdrant"))()
        assert args == {
            "func_hashes": ["h1", "h3"],
            "backend": "qdrant",
            "exclude_sample_id": "this",
        }
        assert [m["family"] for m in value["matches"]] == ["FamilyA"]

    def test_a_store_that_cannot_be_built_still_says_why_naming_no_password(
        self, monkeypatch: Any
    ) -> None:
        def _broken(_memory: Any) -> Any:
            raise MemoryStoreError("client library missing for http://user:pw-123@q:6333")

        monkeypatch.setitem(
            store_factory._BACKENDS, "qdrant", store_factory.MemoryBackend("qdrant", _broken)
        )
        _args, value = self._step(_settings("qdrant"))()
        assert value["matches"] == []
        assert "client library missing" in value["reason"]
        assert "pw-123" not in value["reason"]

    def test_no_store_is_built_for_a_provider_that_cannot_hash(self) -> None:
        from maljan.pipeline.nodes import _function_matches_step

        provider = SimpleNamespace(capabilities=SimpleNamespace(provides_function_hashes=False))
        container = SimpleNamespace(
            config=_settings("qdrant"), get_static_provider=lambda: provider
        )
        state = {"static_sample_path": "/mirror/s.bin", "file_hash": "this"}
        assert _function_matches_step(container, state) is None  # type: ignore[arg-type]
        assert _FakeQdrant.built == []

    def test_a_registered_backend(self, third_backend: Any) -> None:
        _args, value = self._step(third_backend)()
        assert [(m["func_hash"], m["family"]) for m in value["matches"]] == [("h1", "FamilyA")]


class TestTheStaticAnalystHintUsesTheConfiguredBackend:
    @staticmethod
    def _hint(config: Any) -> tuple[str, list[str]]:
        from maljan.agents.static_analyst import StaticAnalyst

        asked: list[str] = []

        def _hashes(job: Any) -> list[tuple[str, str]]:
            asked.append(job.mirror_sample_path)
            return [("f1", "h1")]

        provider = SimpleNamespace(
            capabilities=SimpleNamespace(provides_function_hashes=True),
            function_hashes=_hashes,
        )
        analyst = SimpleNamespace(
            _provider=lambda: provider,
            logger=SimpleNamespace(info=lambda *a: None, warning=lambda *a: None),
        )
        settings = SimpleNamespace(
            memory=config.memory,
            preprocessing=SimpleNamespace(
                use_function_hash_attribution=True, function_hash_max_matches=8
            ),
        )
        with patch("maljan.core.config.get_settings", return_value=settings):
            hint = StaticAnalyst._compute_function_hash_hint(analyst, "/m/s.bin", "this")  # type: ignore[arg-type]
        return hint, asked

    def test_a_backend_without_function_hashes_asks_the_provider_nothing(self) -> None:
        assert self._hint(_settings("memory")) == ("", [])

    def test_a_registered_backend_gives_the_prior(self, third_backend: Any) -> None:
        hint, asked = self._hint(third_backend)
        assert "FamilyA" in hint and asked == ["/m/s.bin"]


class TestTheCommandLineUsesTheFactory:
    def test_the_dry_run_counts_on_any_backend(self, monkeypatch: Any) -> None:
        from typer.testing import CliRunner

        from maljan import cli

        _seed_cases(THIN, RICH, FAILED)
        monkeypatch.setattr(cli, "Settings", lambda: _settings("qdrant"))
        result = CliRunner().invoke(cli.app, ["memory", "purge-low-quality", "--dry-run"])
        assert result.exit_code == 0, result.output
        assert "would remove 2 of 3 cases" in result.output
        assert _FakeQdrant.built[-1].deleted == []


class TestABackendIsSelectedAndConfiguredThroughTheSettings:
    def test_saving_an_unregistered_backend_is_refused(self) -> None:
        from app.services.settings_service import SettingsService, SettingsValidationError

        with pytest.raises(SettingsValidationError) as refused:
            SettingsService(db=None).check_keys({"core.memory.backend": "vectorhub"})  # type: ignore[arg-type]
        assert "qdrant" in refused.value.errors["core.memory.backend"]
        SettingsService(db=None).check_keys({"core.memory.backend": "memory"})  # type: ignore[arg-type]

    def test_a_stored_unregistered_backend_still_loads_and_the_factory_says_so(self) -> None:
        cfg = Settings(_env_file=None, memory={"backend": "vectorhub", "top_k": 7})
        assert (cfg.memory.backend, cfg.memory.top_k) == ("vectorhub", 7)
        with pytest.raises(store_factory.MemoryBackendNotConfiguredError) as missing:
            store_factory.build_memory_store(cfg)
        assert missing.value.unavailable is False

    def test_a_registered_backend_reads_its_own_settings_under_its_id(
        self, third_backend: Any
    ) -> None:
        own = store_factory.backend_settings(third_backend, "third")
        assert isinstance(own, _ThirdSettings) and own.endpoint == "http://third:1"

    def test_its_settings_reach_the_catalogue_with_the_annotations_it_registered(
        self, third_backend: Any
    ) -> None:
        from maljan.core.settings_catalog import core_catalog

        by_key = {e.key: e for e in core_catalog()}
        assert by_key["core.memory.third.endpoint"].title == "Third endpoint"
        assert by_key["core.memory.third.token"].secret is True
        assert "third" in by_key["core.memory.backend"].choices

    def test_the_backend_choice_is_the_registry(self) -> None:
        from maljan.core.settings_catalog import core_catalog

        (entry,) = [e for e in core_catalog() if e.key == "core.memory.backend"]
        assert entry.type == "enum"
        assert entry.choices == list(store_factory.memory_backends())

    def test_an_installed_package_registers_through_its_entry_point_once_allowed(
        self, monkeypatch: Any
    ) -> None:
        def _register() -> None:
            store_factory.register_memory_backend("packaged", lambda _m: InMemoryStore())

        _installed(monkeypatch, SimpleNamespace(name="packaged", load=lambda: _register))
        try:
            assert "packaged" not in store_factory.memory_backends()
            plugins.load_allowed(["memory:packaged"])
            assert "packaged" in store_factory.memory_backends()
            cfg = Settings(_env_file=None, memory={"backend": "packaged"})
            assert isinstance(store_factory.build_memory_store(cfg), InMemoryStore)
        finally:
            plugins.load_allowed([])
        assert "packaged" not in store_factory.memory_backends()

    def test_a_broken_entry_point_leaves_the_others_registered(self, monkeypatch: Any) -> None:
        def _boom() -> None:
            raise RuntimeError("broken package")

        _installed(monkeypatch, SimpleNamespace(name="broken", load=lambda: _boom))
        plugins.load_allowed(["memory:broken"])
        assert {"memory", "qdrant"} <= set(store_factory.memory_backends())
        assert store_factory.unavailable_backends() == {"broken": "RuntimeError: broken package"}


class TestTheOldFlatKeysAreStillRead:
    def test_flat_keys_land_under_the_backend(self) -> None:
        cfg = Settings(
            _env_file=None,
            memory={
                "qdrant_url": URL,
                "qdrant_collection": "cases",
                "qdrant_function_hash_collection": "hashes",
                "qdrant_api_key": "k",
            },
        )
        own = cfg.memory.qdrant
        assert (own.url, own.collection, own.function_hash_collection) == (URL, "cases", "hashes")
        assert own.api_key is not None and own.api_key.get_secret_value() == "k"

    def test_a_nested_value_wins_over_a_flat_one(self) -> None:
        cfg = Settings(
            _env_file=None, memory={"qdrant_url": "http://old:1", "qdrant": {"url": URL}}
        )
        assert cfg.memory.qdrant.url == URL

    def test_an_older_export_imports_onto_the_new_keys(self) -> None:
        from app.api.v1.settings import _current_keys

        assert _current_keys(
            {"core.memory.qdrant_url": "http://old:1", "core.memory.top_k": 4}
        ) == {"core.memory.top_k": 4, "core.memory.qdrant.url": "http://old:1"}
        both = {"core.memory.qdrant_url": "http://old:1", "core.memory.qdrant.url": URL}
        assert _current_keys(both) == {"core.memory.qdrant.url": URL}


class TestABackendWithoutTheNewMethods:
    def test_one_built_on_the_defaults_degrades_like_any_other(self) -> None:
        from maljan.memory.long_term_memory import MemoryStoreDefaults

        class _Plain(MemoryStoreDefaults):
            def store(self, case: Any) -> None: ...
            def retrieve(self, query: str, top_k: int = 3, exclude_sample_id: Any = None) -> list:
                return []

            def count(self) -> int:
                return 0

            def clear(self) -> None: ...
            def purge_low_quality(self, **_kwargs: Any) -> int:
                return 0

        store_factory.register_memory_backend("plain", lambda _m: _Plain())
        try:
            cfg = SimpleNamespace(backend="plain")
            assert store_factory.build_memory_store(cfg).readiness() == "in process"
            assert store_factory.build_function_hash_store(cfg) is None
        finally:
            store_factory._BACKENDS.pop("plain", None)

    def test_one_lacking_the_interface_is_refused_naming_what_it_lacks(self) -> None:
        class _Old:
            def store(self, case: Any) -> None: ...

        store_factory.register_memory_backend("old", lambda _m: _Old())
        try:
            with pytest.raises(MemoryStoreError, match="readiness"):
                store_factory.build_memory_store(SimpleNamespace(backend="old"))
        finally:
            store_factory._BACKENDS.pop("old", None)


class TestHealthNamesTheBackendOnEveryAnswer:
    def test_a_builder_that_raises_is_a_failure_naming_the_backend_and_no_password(
        self, monkeypatch: Any
    ) -> None:
        def _broken(_memory: Any) -> Any:
            raise MemoryStoreError("bad address http://user:pw-123@q:6333")

        monkeypatch.setitem(
            store_factory._BACKENDS, "qdrant", store_factory.MemoryBackend("qdrant", _broken)
        )
        component = TestHealthProbesTheConfiguredBackend._memory_component(_settings("qdrant"))
        assert component["ok"] is False and component["backend"] == "qdrant"
        assert "pw-123" not in component["error"]

    def test_an_unreachable_store_names_its_backend(self) -> None:
        _FakeQdrant.down = True
        component = TestHealthProbesTheConfiguredBackend._memory_component(_settings("qdrant"))
        assert component["backend"] == "qdrant"

    def test_the_probe_closes_what_it_built(self) -> None:
        TestHealthProbesTheConfiguredBackend._memory_component(_settings("qdrant"))
        assert [c.closed for c in _FakeQdrant.built] == [1]
        _FakeQdrant.down = True
        TestHealthProbesTheConfiguredBackend._memory_component(_settings("qdrant"))
        assert [c.closed for c in _FakeQdrant.built] == [1, 1]


class TestTheFunctionHashStoreIsBuiltOncePerSettings:
    def test_asked_twice_one_client(self) -> None:
        first = store_factory.build_function_hash_store(_settings("qdrant"))
        second = store_factory.build_function_hash_store(_settings("qdrant"))
        assert first is second and len(_FakeQdrant.built) == 1

    def test_other_settings_another_store_and_the_old_one_closed(self) -> None:
        store_factory.build_function_hash_store(_settings("qdrant"))
        other = Settings(_env_file=None, memory={"qdrant": {"url": URL, "api_key": "other"}})
        store_factory.build_function_hash_store(other)
        assert [c.api_key for c in _FakeQdrant.built] == ["k", "other"]
        assert [c.closed for c in _FakeQdrant.built] == [1, 0]

    def test_forgetting_closes_what_was_held(self) -> None:
        store_factory.build_function_hash_store(_settings("qdrant"))
        store_factory.forget_built_stores()
        assert [c.closed for c in _FakeQdrant.built] == [1]


class TestTheJudgeReadsAndHoldsThroughTheConfiguredBackend:
    @staticmethod
    def _run(config: Any) -> tuple[list[dict[str, Any]], Any, list[str]]:
        from maljan.pipeline import nodes

        asked: list[str] = []

        def _hashes(job: Any) -> list[tuple[str, str]]:
            asked.append(job.mirror_sample_path)
            return [("f1", "h1"), ("f2", "h2")]

        provider = SimpleNamespace(
            capabilities=SimpleNamespace(provides_function_hashes=True), function_hashes=_hashes
        )
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(config)
        container.get_static_provider = lambda: provider  # type: ignore[method-assign]
        state = {"static_sample_path": "/mirror/s.bin", "file_hash": "this"}
        with (
            patch("maljan.core.config.get_settings", return_value=config),
            patch.object(nodes, "_assessed_family", return_value="FamilyB"),
        ):
            report = nodes._function_hash_attribution(container, state, bundle=None)  # type: ignore[arg-type]
        return report, container.pending_function_hashes, asked

    def test_a_backend_without_function_hashes_holds_nothing_and_asks_nothing(self) -> None:
        report, held, asked = self._run(_settings("memory"))
        assert (report, held, asked) == ([], None, [])

    def test_qdrant_reads_and_holds_its_function_hash_collection(self) -> None:
        _FakeQdrant.seed = {
            "maljan_function_hashes_v1": {
                1: {"func_hash": "h1", "family": "FamilyA", "sample_id": "older", "func_name": "f1"}
            }
        }
        report, held, asked = self._run(_settings("qdrant"))
        assert [row["family"] for row in report] == ["FamilyA"]
        store, sample_id, family, functions = held
        assert isinstance(store, FunctionHashStore)
        assert store._collection == "maljan_function_hashes_v1"
        assert (sample_id, family, functions) == ("this", "FamilyB", [("f1", "h1"), ("f2", "h2")])
        assert asked == ["/mirror/s.bin"]


class TestTheContainerStoreIsTheFactorys:
    """The store a run writes its case to is the one every other caller builds."""

    @staticmethod
    def _container_store(config: Any) -> Any:
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(config)
        first = container.get_memory_store()
        assert container.get_memory_store() is first  # built once per container
        return first

    def test_for_every_registered_backend(self, third_backend: Any) -> None:
        configs = {
            "memory": _settings("memory"),
            "qdrant": _settings("qdrant"),
            "third": third_backend,
        }
        assert set(configs) == set(store_factory.memory_backends())
        for backend, config in configs.items():
            ours = self._container_store(config)
            theirs = store_factory.build_memory_store(config)
            assert type(ours) is type(theirs), backend
            if isinstance(ours, QdrantStore):
                assert (ours._url, ours._collection, ours._function_hash_collection) == (
                    theirs._url,
                    theirs._collection,
                    theirs._function_hash_collection,
                )
            if backend == "third":
                assert (
                    ours.readiness()
                    == theirs.readiness()
                    == ("third backend ready at http://third:1")
                )

    def test_the_container_reaches_qdrant_with_the_configured_key(self) -> None:
        self._container_store(_settings("qdrant"))
        assert [(c.url, c.api_key) for c in _FakeQdrant.built] == [(URL, "k")]


class TestABrokenPackageBackendNeverStopsTheSettings:
    @pytest.fixture
    def broken(self, monkeypatch: Any) -> Any:
        def _boom() -> None:
            raise ImportError("vectorhub_client is not installed")

        _installed(monkeypatch, SimpleNamespace(name="vectorhub", load=lambda: _boom))
        plugins.install_allow_list(["memory:vectorhub"])
        plugins.load_allowed(["memory:vectorhub"])
        return Settings(_env_file=None, memory={"backend": "vectorhub", "top_k": 5})

    def test_the_settings_load_with_the_rest_intact(self, broken: Any) -> None:
        assert broken.memory.top_k == 5
        assert broken.memory.qdrant.url == "http://localhost:6333"
        assert "vectorhub" in store_factory.unavailable_backends()

    def test_every_build_says_the_backend_is_unavailable_and_why(self, broken: Any) -> None:
        with pytest.raises(store_factory.MemoryBackendNotConfiguredError) as missing:
            store_factory.build_memory_store(broken)
        assert missing.value.unavailable is True
        assert "vectorhub_client is not installed" in missing.value.reason

    def test_health_reports_it_unavailable_with_the_reason(self, broken: Any) -> None:
        component = TestHealthProbesTheConfiguredBackend._memory_component(broken)
        assert component["ok"] is False and component["detail"] == "unavailable"
        assert component["backend"] == "vectorhub"
        assert "vectorhub_client is not installed" in component["error"]

    def test_a_run_goes_on_without_memory(self, broken: Any) -> None:
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(broken)
        with pytest.raises(store_factory.MemoryBackendNotConfiguredError):
            container.get_memory_store()
        assert TestTheJudgeReadsAndHoldsThroughTheConfiguredBackend._run(broken)[:2] == ([], None)
        assert TestTheFunctionMatchStepUsesTheConfiguredBackend._step(broken)()[1]["matches"] == []


class TestOneMapOfMovedKeys:
    def test_the_flat_memory_keys_are_read_off_the_renamed_settings(self) -> None:
        from maljan.core.config import LEGACY_MEMORY_KEYS
        from maljan.core.settings_annotations import RENAMED_SETTINGS

        assert LEGACY_MEMORY_KEYS == {
            old.removeprefix("core.memory."): tuple(new.removeprefix("core.memory.").split(".", 1))
            for old, new in RENAMED_SETTINGS.items()
            if old.startswith("core.memory.")
        }
        assert LEGACY_MEMORY_KEYS["qdrant_url"] == ("qdrant", "url")

    def test_a_patch_reads_an_old_key_as_the_new_one(self) -> None:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.api.v1 import settings as settings_module
        from app.database import get_db
        from app.deps import require_admin

        app = FastAPI()
        app.include_router(settings_module.router, prefix="/api/v1")
        app.dependency_overrides[require_admin] = lambda: SimpleNamespace(id=None)
        app.dependency_overrides[get_db] = lambda: AsyncMock()
        saved: dict[str, Any] = {}

        async def _save(self: Any, changes: dict[str, Any], **_kw: Any) -> Any:
            saved.update(changes)
            return SimpleNamespace(applied=sorted(changes), applies={})

        with (
            patch.object(settings_module, "_unprobed_models_in", AsyncMock(return_value=[])),
            patch.object(settings_module, "_agent_warnings", AsyncMock(return_value={})),
            patch.object(settings_module.SettingsService, "save", _save),
        ):
            response = TestClient(app).patch(
                "/api/v1/settings", json={"changes": {"core.memory.qdrant_url": URL}}
            )
        assert response.status_code == 200, response.text
        assert saved == {"core.memory.qdrant.url": URL}


class TestARunningJobKeepsTheStoreItHolds:
    """A settings change never closes the function-hash store under a job."""

    @staticmethod
    def _job(config: Any) -> Any:
        from maljan.core.container import ServiceContainer
        from maljan.pipeline import nodes

        provider = SimpleNamespace(
            capabilities=SimpleNamespace(provides_function_hashes=True),
            function_hashes=lambda _job: [("f1", "h1"), ("f2", "h2")],
        )
        container = ServiceContainer(config)
        container.get_static_provider = lambda: provider  # type: ignore[method-assign]
        state = {"static_sample_path": "/mirror/s.bin", "file_hash": "this"}
        with (
            patch("maljan.core.config.get_settings", return_value=config),
            patch.object(nodes, "_assessed_family", return_value="FamilyB"),
        ):
            nodes._function_hash_attribution(container, state, bundle=None)  # type: ignore[arg-type]
        assert container.pending_function_hashes is not None
        return container

    def test_the_job_writes_after_a_settings_change_and_the_old_store_closes_after(self) -> None:
        container = self._job(_settings("qdrant"))
        (held_client,) = _FakeQdrant.built

        other = Settings(_env_file=None, memory={"qdrant": {"url": URL, "api_key": "other"}})
        assert store_factory.build_function_hash_store(other) is not None  # the change
        assert held_client.closed == 0  # still held by the running job

        assert container.remember_the_run() is True  # the job's write succeeds
        assert set(held_client.collections["maljan_function_hashes_v1"]) != set()
        assert held_client.closed == 1  # closed once the job let go
        assert _FakeQdrant.built[-1].closed == 0  # the new store stays open

    def test_a_job_that_ends_without_writing_lets_go_at_teardown(self) -> None:
        container = self._job(_settings("qdrant"))
        (held_client,) = _FakeQdrant.built
        store_factory.forget_built_stores()
        assert held_client.closed == 0
        asyncio.run(container.aclose())
        assert held_client.closed == 1

    def test_an_unchanged_store_stays_open_after_the_job(self) -> None:
        container = self._job(_settings("qdrant"))
        container.remember_the_run()
        assert [c.closed for c in _FakeQdrant.built] == [0]

    def test_two_holders_the_last_one_closes(self) -> None:
        first = store_factory.acquire_function_hash_store(_settings("qdrant"))
        second = store_factory.acquire_function_hash_store(_settings("qdrant"))
        assert first is second
        store_factory.forget_built_stores()
        store_factory.release_function_hash_store(first)
        assert _FakeQdrant.built[0].closed == 0
        store_factory.release_function_hash_store(second)
        assert _FakeQdrant.built[0].closed == 1

    def test_a_read_in_progress_keeps_its_store(self) -> None:
        with store_factory.leased_function_hash_store(_settings("qdrant")) as store:
            store_factory.forget_built_stores()
            assert store is not None and store.match(["h1"]) == []
            assert _FakeQdrant.built[0].closed == 0
        assert _FakeQdrant.built[0].closed == 1


class TestHoldsAreNeverLost:
    def test_a_hold_is_counted_before_any_replacement_can_close_the_store(self) -> None:
        """A reader and a settings flipper race; no store is ever closed while held."""
        import threading

        one = _settings("qdrant")
        two = Settings(_env_file=None, memory={"qdrant": {"url": URL, "api_key": "two"}})
        closed_while_held: list[Any] = []
        stop = threading.Event()

        def _flip() -> None:
            while not stop.is_set():
                store_factory.build_function_hash_store(two)
                store_factory.build_function_hash_store(one)

        flipper = threading.Thread(target=_flip)
        flipper.start()
        try:
            for _ in range(300):
                store = store_factory.acquire_function_hash_store(one)
                if store is not None and store._client.closed:
                    closed_while_held.append(store)
                store_factory.release_function_hash_store(store)
        finally:
            stop.set()
            flipper.join()
        assert closed_while_held == []

    def test_a_replaced_pending_write_lets_go_of_its_store(self) -> None:
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(_settings("qdrant"))
        first = store_factory.acquire_function_hash_store(_settings("qdrant"))
        container.hold_function_hashes(first, "a", "FamilyA", [("f", "h")])
        store_factory.forget_built_stores()  # the first store is now retired, still held
        second = store_factory.acquire_function_hash_store(_settings("qdrant"))
        container.hold_function_hashes(second, "b", "FamilyB", [("f", "h")])
        assert _FakeQdrant.built[0].closed == 1  # let go of when it was replaced
        assert container.pending_function_hashes[0] is second

    def test_a_hold_handed_over_after_teardown_is_let_go_of_at_once(self) -> None:
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(_settings("qdrant"))
        asyncio.run(container.aclose())
        late = store_factory.acquire_function_hash_store(_settings("qdrant"))
        store_factory.forget_built_stores()  # retired, held only by the late hand-over
        container.hold_function_hashes(late, "a", "FamilyA", [("f", "h")])
        assert container.pending_function_hashes is None
        assert _FakeQdrant.built[0].closed == 1


class TestABrokenPackageWithAnotherEntryPointName:
    def test_its_failure_is_its_own_and_the_selected_id_names_the_installed_plugins(
        self, monkeypatch: Any
    ) -> None:
        """A plugin is known by its entry point's name, the one id it may register."""

        def _boom() -> None:
            raise ImportError("vectorhub_client is not installed")

        _installed(monkeypatch, SimpleNamespace(name="vectorhub-plugin", load=lambda: _boom))
        plugins.install_allow_list(["memory:vectorhub-plugin"])
        plugins.load_allowed(["memory:vectorhub-plugin"])
        cfg = Settings(_env_file=None, memory={"backend": "vectorhub"})
        assert store_factory.unavailable_backends() == {
            "vectorhub-plugin": "ImportError: vectorhub_client is not installed"
        }
        with pytest.raises(store_factory.MemoryBackendNotConfiguredError) as missing:
            store_factory.build_memory_store(cfg)
        assert missing.value.unavailable is True
        assert "the installed memory plugins are vectorhub-plugin" in missing.value.reason
        assert "must be the backend id it registers" in missing.value.reason
        component = TestHealthProbesTheConfiguredBackend._memory_component(cfg)
        assert component["ok"] is False and component["detail"] == "unavailable"
        assert "vectorhub-plugin" in component["error"]

    def test_with_no_failed_package_an_unknown_id_is_not_configured(self) -> None:
        cfg = Settings(_env_file=None, memory={"backend": "vectorhub"})
        component = TestHealthProbesTheConfiguredBackend._memory_component(cfg)
        assert component["ok"] is None and component["detail"] == "not configured"


class TestAnUnchangedStoredChoiceIsNotCheckedAgain:
    def test_re_sending_the_stored_id_saves_the_other_keys(self) -> None:
        from app.services.settings_service import SettingsService

        stored = {"core.memory.backend": "vectorhub"}
        SettingsService(db=None).check_keys(  # type: ignore[arg-type]
            {"core.memory.backend": "vectorhub", "core.memory.top_k": 4}, stored
        )

    def test_changing_to_another_unknown_id_is_still_refused(self) -> None:
        from app.services.settings_service import SettingsService, SettingsValidationError

        with pytest.raises(SettingsValidationError):
            SettingsService(db=None).check_keys(  # type: ignore[arg-type]
                {"core.memory.backend": "otherhub"}, {"core.memory.backend": "vectorhub"}
            )
