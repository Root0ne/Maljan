"""One factory builds the configured memory store for every caller.

Two backends throughout: the in-process store, and Qdrant through its own
client against a fake server. The enrichment worker, the API's purge dry run,
``/health``, the function-hash steps and the command line each get the store
``memory.backend`` selects, and none of them names a backend: a third backend
registered at run time is used by the same callers unchanged.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

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
        _FakeQdrant.built.append(self)

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
def _fake_qdrant(monkeypatch: pytest.MonkeyPatch) -> type[_FakeQdrant]:
    _FakeQdrant.built = []
    _FakeQdrant.down = False
    _FakeQdrant.seed = {}
    monkeypatch.setattr("qdrant_client.QdrantClient", _FakeQdrant)
    return _FakeQdrant


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
        def readiness(self) -> str:
            return "third backend ready"

        def function_hash_store(self) -> Any:
            return hashes

    store_factory.register_memory_backend("third", lambda _memory: _Third())
    yield SimpleNamespace(memory=SimpleNamespace(backend="third"))
    store_factory._BACKENDS.pop("third", None)


def _settings(backend: str) -> Settings:
    return Settings(
        _env_file=None,
        memory={"backend": backend, "qdrant_url": URL, "qdrant_api_key": "k"},
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
        assert store.readiness() == "third backend ready"

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
            memory={"backend": "qdrant", "qdrant_url": "http://user:pw-123@q:6333"},
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
        store = self._built(SimpleNamespace(memory=third_backend.memory))
        assert store.readiness() == "third backend ready"


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
        overrides = {"memory.backend": backend, "memory.qdrant_url": URL}
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

        with (
            patch.object(runtime_config, "core", AsyncMock(return_value=settings)),
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
        component = self._memory_component(SimpleNamespace(memory=third_backend.memory))
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

    def test_a_store_that_cannot_be_built_still_says_why(self, monkeypatch: Any) -> None:
        def _broken(_memory: Any) -> Any:
            raise MemoryStoreError("client library missing")

        monkeypatch.setitem(store_factory._BACKENDS, "qdrant", _broken)
        _args, value = self._step(_settings("qdrant"))()
        assert value["matches"] == []
        assert "client library missing" in value["reason"]

    def test_a_registered_backend(self, third_backend: Any) -> None:
        _args, value = self._step(SimpleNamespace(memory=third_backend.memory))()
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
