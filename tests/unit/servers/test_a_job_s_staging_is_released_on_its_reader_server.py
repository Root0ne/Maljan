"""What a job's readings staged on a server of their own goes when the job ends (T-325).

A reading on the analysis or network server in a container of its own (capa's
and FLOSS's scratch, the unpacker's carves, a capture handed over) writes
under ``<staging>/<job>`` there, which the server's staging TTL used to be the
only thing to remove. At the job's end the worker now sends each server a
reading ran on ``release_job`` with the job's id, and the server removes that
job's directory alone: no id names anything else, a link standing there is
unlinked and never followed, and a server started for one job releases only
that one. The call is bounded; a server that lacks it, refuses, raises or
does not answer leaves the directory to its TTL and never fails the job.
"""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import time
from functools import cache
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from maljan.agents.tool_pinning import DELIVERY_TOOLS
from maljan.tools import readers, staging
from maljan.tools.readers import RELEASE_JOB

JOB = "a3d1c0de-0000-4000-8000-000000000025"
OTHER = "a3d1c0de-0000-4000-8000-000000000026"
SERVICES = Path(__file__).resolve().parents[3] / "services"


@pytest.fixture
def base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The server's staging base, with no job's leaf named: a server serving many jobs."""
    root = tmp_path / "staging"
    root.mkdir(mode=0o700)
    monkeypatch.setenv(staging.STAGING_DIR_ENV, str(root))
    monkeypatch.delenv(staging.STAGING_JOB_ENV, raising=False)
    return root


def _staged(base: Path, job: str) -> Path:
    """A job's directory as its readings leave it: scratch and a carve, nested."""
    job_dir = base / staging.job_directory_name(job)
    (job_dir / staging.CAPA_DIRECTORY).mkdir(parents=True)
    (job_dir / staging.CAPA_DIRECTORY / "scratch.bin").write_bytes(b"MZ")
    (job_dir / staging.CARVED_DIRECTORY / ("a" * 64)).mkdir(parents=True)
    (job_dir / staging.CARVED_DIRECTORY / ("a" * 64) / "unpacked.exe").write_bytes(b"MZ")
    return job_dir


def _outside(tmp_path: Path) -> Path:
    """A directory outside the staging base that no release may touch."""
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "keep.txt").write_text("kept")
    return target


# -- The server's side --------------------------------------------------------------------


def test_the_job_s_directory_is_removed_and_a_sibling_job_s_is_kept(base: Path) -> None:
    mine, theirs = _staged(base, JOB), _staged(base, OTHER)
    assert readers.serve_release(JOB) == {"released": True}
    assert not mine.exists()
    assert (theirs / staging.CAPA_DIRECTORY / "scratch.bin").read_bytes() == b"MZ"
    assert base.is_dir()


def test_a_job_that_staged_nothing_is_released_as_nothing_there(base: Path) -> None:
    assert readers.serve_release(JOB) == {"released": True}
    assert base.is_dir() and list(base.iterdir()) == []


@pytest.mark.parametrize(
    "hostile",
    [
        "..",
        "../..",
        "../elsewhere",
        f"../{staging.job_directory_name(OTHER)}",
        "/",
        "/etc",
        "/tmp",
        "a/../../elsewhere",
        "job-x/../../elsewhere",
        f"{JOB}/..",
        ".",
        "\x00",
        "..\\..\\elsewhere",
    ],
)
def test_no_job_id_names_anything_but_its_own_directory(
    hostile: str, base: Path, tmp_path: Path
) -> None:
    outside = _outside(tmp_path)
    other = _staged(base, OTHER)
    said = readers.serve_release(hostile)
    assert said == {"released": True}, said
    assert (outside / "keep.txt").read_text() == "kept"
    assert (other / staging.CAPA_DIRECTORY / "scratch.bin").exists()
    assert base.is_dir()
    # The one directory the id composes, and nothing else, is what it names.
    name = staging.job_directory_name(hostile)
    assert staging.is_job_directory_name(name) and Path(name).name == name


def test_a_link_standing_for_the_job_s_directory_is_unlinked_and_its_target_kept(
    base: Path, tmp_path: Path
) -> None:
    outside = _outside(tmp_path)
    link = base / staging.job_directory_name(JOB)
    link.symlink_to(outside, target_is_directory=True)
    assert readers.serve_release(JOB) == {"released": True}
    assert not link.is_symlink() and not link.exists()
    assert (outside / "keep.txt").read_text() == "kept"


def test_a_link_inside_the_job_s_directory_is_never_followed(base: Path, tmp_path: Path) -> None:
    outside = _outside(tmp_path)
    job_dir = _staged(base, JOB)
    (job_dir / staging.CARVED_DIRECTORY / "out").symlink_to(outside, target_is_directory=True)
    (job_dir / "file-link").symlink_to(outside / "keep.txt")
    assert readers.serve_release(JOB) == {"released": True}
    assert not job_dir.exists()
    assert (outside / "keep.txt").read_text() == "kept"


@pytest.mark.parametrize("job", ["", "   ", None, 7, ["x"], {"job": "x"}])
def test_a_release_with_no_job_id_is_refused_and_removes_nothing(job: Any, base: Path) -> None:
    other = _staged(base, OTHER)
    said = readers.serve_release(job)
    assert "error" in said and "released" not in said
    assert other.exists()


def test_a_server_started_for_one_job_releases_only_that_job(
    base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mine, theirs = _staged(base, JOB), _staged(base, OTHER)
    monkeypatch.setenv(staging.STAGING_JOB_ENV, staging.job_directory_name(JOB))
    said = readers.serve_release(OTHER)
    assert "error" in said and theirs.exists()
    assert readers.serve_release(JOB) == {"released": True}
    assert not mine.exists()


def test_a_removal_that_failed_is_answered_and_never_raised(
    base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _staged(base, JOB)
    monkeypatch.setattr(staging, "remove_tree", lambda root: False)
    assert readers.serve_release(JOB) == {"released": False}

    def broken(root: Path) -> bool:
        raise OSError("read-only file system")

    monkeypatch.setattr(staging, "remove_tree", broken)
    said = readers.serve_release(JOB)
    assert said["error"].startswith("OSError")
    # No host path crosses back to the worker.
    assert str(base) not in said["error"]


@cache
def _server(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        f"{name}_mcp_server_release", SERVICES / f"{name}-mcp" / "server.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("name", ["analysis", "network"])
def test_each_reading_server_offers_the_call_as_a_delivery_primitive(name: str, base: Path) -> None:
    module = _server(name)
    assert RELEASE_JOB in {need.name for need in module.TOOL_NEEDS}
    assert RELEASE_JOB in DELIVERY_TOOLS
    tools = {tool.name for tool in asyncio.run(module.mcp.list_tools())}
    assert {RELEASE_JOB, readers.RUN_READER} <= tools
    job_dir = _staged(base, JOB)
    assert module.release_job(JOB) == {"released": True}
    assert not job_dir.exists()
    assert "error" in module.release_job("")


# -- The worker's side ----------------------------------------------------------------------


class _Handle:
    def __init__(self, tools: list[str], answer: Any = None, raises: Exception | None = None):
        self.is_open = True
        self._tools = tools
        self.answer = {"released": True} if answer is None else answer
        self.raises = raises
        self.sent: list[tuple[str, dict[str, Any], float | None]] = []

    def all_tool_names(self) -> list[str]:
        return list(self._tools)

    async def deliver(self, tool: str, args: dict[str, Any], timeout: float | None = None) -> Any:
        self.sent.append((tool, dict(args), timeout))
        if self.raises is not None:
            raise self.raises
        return self.answer if tool == RELEASE_JOB else {"value": None}


class _Registry:
    def __init__(self, handles: dict[str, _Handle]) -> None:
        self.handles = handles
        self.attached: list[tuple[str, str, str]] = []

    def tools_for_ref(self, ref: Any, job: str, **_: Any) -> tuple[list[Any], list[str]]:
        self.attached.append((ref.server, ref.name, job))
        return [], []

    def get(self, key: str) -> _Handle:
        return self.handles[key]


def _container(registry: _Registry) -> Any:
    return SimpleNamespace(
        job_key=lambda: JOB,
        get_server_registry=lambda: registry,
        get_truncation_ledger=lambda: None,
    )


@pytest.fixture
def waits(monkeypatch: pytest.MonkeyPatch) -> list[float | None]:
    """Each coroutine run on this thread, its hard cap kept."""
    from maljan.agents import base_agent

    held: list[float | None] = []

    def blocking(coro: Any, hard_timeout: float | None, label: str = "") -> Any:
        held.append(hard_timeout)
        return asyncio.run(coro)

    monkeypatch.setattr(base_agent, "run_coro_blocking", blocking)
    return held


def _read_once(container: Any, key: str) -> None:
    """One reading sent to server ``key`` through its place, as the pack sends one."""
    from maljan.pipeline import nodes

    place = nodes._reader_place(container, key, SimpleNamespace(), None)
    place.call({"reader": "hashes", "arguments": {}, "job": JOB}, 1.0)


def test_each_server_a_reading_ran_on_is_sent_the_job_s_release(waits: list[Any]) -> None:
    from maljan.pipeline import nodes

    analysis = _Handle([readers.RUN_READER, RELEASE_JOB])
    network = _Handle([readers.RUN_READER, RELEASE_JOB])
    idle = _Handle([readers.RUN_READER, RELEASE_JOB])
    registry = _Registry({"analysis": analysis, "network": network, "idle": idle})
    container = _container(registry)
    _read_once(container, "analysis")
    _read_once(container, "analysis")
    _read_once(container, "network")
    assert nodes.release_reader_staging(container) == ["analysis", "network"]
    for handle in (analysis, network):
        assert handle.sent[-1] == (RELEASE_JOB, {"job": JOB}, nodes.RELEASE_SECONDS)
        assert [tool for tool, _a, _t in handle.sent].count(RELEASE_JOB) == 1
    # A server no reading ran on is never asked.
    assert idle.sent == []
    assert ("idle", RELEASE_JOB, JOB) not in registry.attached
    # Each call is held to its few seconds.
    assert waits[-1] is not None and waits[-1] <= nodes.RELEASE_SECONDS + 1.0


def test_a_job_whose_readings_all_ran_here_asks_no_server(waits: list[Any]) -> None:
    from maljan.pipeline import nodes

    registry = _Registry({"analysis": _Handle([RELEASE_JOB])})
    assert nodes.release_reader_staging(_container(registry)) == []
    assert registry.attached == []


def test_a_server_built_before_the_call_is_left_to_its_ttl_without_a_failure(
    waits: list[Any], caplog: pytest.LogCaptureFixture
) -> None:
    from maljan.pipeline import nodes

    old = _Handle([readers.RUN_READER])
    container = _container(_Registry({"analysis": old}))
    _read_once(container, "analysis")
    assert nodes.release_reader_staging(container) == []
    assert all(tool != RELEASE_JOB for tool, _a, _t in old.sent)


@pytest.mark.parametrize(
    ("answer", "raises"),
    [
        ({"error": "this server stages for another job"}, None),
        ({"released": False}, None),
        ("not an object", None),
        (None, TimeoutError("no answer in time")),
        (None, RuntimeError("the session closed")),
    ],
)
def test_a_release_that_fails_is_logged_and_never_fails_the_job(
    answer: Any, raises: Exception | None, waits: list[Any]
) -> None:
    from maljan.pipeline import nodes

    handle = _Handle([readers.RUN_READER, RELEASE_JOB])
    container = _container(_Registry({"analysis": handle}))
    _read_once(container, "analysis")
    handle.answer, handle.raises = answer, raises
    assert nodes.release_reader_staging(container) == []


def test_a_server_that_cannot_be_attached_is_left_to_its_ttl(waits: list[Any]) -> None:
    from maljan.pipeline import nodes

    handle = _Handle([readers.RUN_READER, RELEASE_JOB])
    container = _container(_Registry({"analysis": handle}))
    _read_once(container, "analysis")
    handle.is_open = False
    assert nodes.release_reader_staging(container) == []
    assert all(tool != RELEASE_JOB for tool, _a, _t in handle.sent)


def test_what_was_noted_for_another_job_is_never_released_for_this_one(
    waits: list[Any],
) -> None:
    from maljan.pipeline import nodes

    handle = _Handle([readers.RUN_READER, RELEASE_JOB])
    container = _container(_Registry({"analysis": handle}))
    _read_once(container, "analysis")
    container.job_key = lambda: OTHER
    assert nodes.release_reader_staging(container) == []


# -- The job's teardown -----------------------------------------------------------------------


class _TornDown:
    def __init__(self, order: list[str]) -> None:
        self.order = order

    def close_all(self) -> list[Any]:
        self.order.append("close_all")
        return []

    def still_open(self) -> list[Any]:
        return []


def _service_container(tmp_path: Path) -> Any:
    from maljan.core.container import ServiceContainer
    from maljan.core.settings_overrides import build_settings

    return ServiceContainer(build_settings({}), mock=True, samples_dir=str(tmp_path), job_id=JOB)


def test_the_release_runs_at_teardown_before_the_servers_are_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.pipeline import nodes

    order: list[str] = []
    container = _service_container(tmp_path)
    container._server_registry_cache = _TornDown(order)

    def release(held: Any) -> list[str]:
        assert held is container
        order.append("release")
        return []

    monkeypatch.setattr(nodes, "release_reader_staging", release)
    asyncio.run(container.aclose())
    assert order == ["release", "close_all"]


@pytest.mark.parametrize("ending", ["slow", "raises"])
def test_a_release_that_hangs_or_raises_never_holds_or_fails_the_teardown(
    ending: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.core import container as container_module
    from maljan.pipeline import nodes

    order: list[str] = []
    container = _service_container(tmp_path)
    container._server_registry_cache = _TornDown(order)
    monkeypatch.setattr(container_module, "_RELEASE_BUDGET", 0.2)

    def release(_held: Any) -> list[str]:
        if ending == "raises":
            raise RuntimeError("the registry is gone")
        time.sleep(1.5)
        return []

    monkeypatch.setattr(nodes, "release_reader_staging", release)

    async def torn_down() -> float:
        # Timed inside the loop: the loop's own end waits for its threads.
        began = time.monotonic()
        await container.aclose()
        return time.monotonic() - began

    assert asyncio.run(torn_down()) < 1.2
    assert order == ["close_all"]


def test_no_release_is_asked_of_a_job_that_attached_no_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.pipeline import nodes

    called: list[Any] = []
    monkeypatch.setattr(nodes, "release_reader_staging", called.append)
    asyncio.run(_service_container(tmp_path).aclose())
    assert called == []


def test_the_staging_base_itself_is_never_released(base: Path) -> None:
    # Whatever the id, the target is one level below the base, never the base.
    for job in ("x", "..", "/"):
        target = base / staging.job_directory_name(job)
        assert target.parent == base and target != base
    assert os.path.isdir(base)


# -- The review's round: threads, parallel calls, a kind of its own, cancellation ----------


class _SlowToSet:
    """A container whose attribute writes take a moment: the window two threads race in."""

    def __init__(self, registry: _Registry) -> None:
        self.job_key = lambda: JOB
        self.get_server_registry = lambda: registry
        self.get_truncation_ledger = lambda: None

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "_reading_servers_held":
            time.sleep(0.01)
        object.__setattr__(self, name, value)


def test_two_threads_noting_their_servers_at_once_lose_neither() -> None:
    import threading

    from maljan.pipeline import nodes

    keys = [f"server{n}" for n in range(8)]
    for _round in range(5):
        container = _SlowToSet(_Registry({}))
        start = threading.Barrier(len(keys))

        def note(key: str, held: Any = container, gate: Any = start) -> None:
            gate.wait()
            nodes._note_reading_server(held, key)

        threads = [threading.Thread(target=note, args=(key,)) for key in keys]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert nodes._noted_reading_servers(container, JOB) == sorted(keys)


# What one release call takes. The bounds below are multiples of it, so a loaded
# machine stretches the call and the bound together.
RELEASE_CALL_SECONDS = 3.0


class _SlowHandle(_Handle):
    async def deliver(self, tool: str, args: dict[str, Any], timeout: float | None = None) -> Any:
        await asyncio.sleep(RELEASE_CALL_SECONDS)
        return await super().deliver(tool, args, timeout)


def test_every_server_is_asked_at_once(waits: list[Any]) -> None:
    from maljan.pipeline import nodes

    handles = {key: _SlowHandle([readers.RUN_READER, RELEASE_JOB]) for key in ("a", "b", "c")}
    container = _container(_Registry(dict(handles)))
    for key in handles:
        _read_once(container, key)
    began = time.monotonic()
    assert nodes.release_reader_staging(container) == ["a", "b", "c"]
    # Three calls side by side take one call's time, not three.
    assert time.monotonic() - began < 2 * RELEASE_CALL_SECONDS


def test_a_release_that_outlasts_its_cap_is_abandoned_not_waited_for(
    waits: list[Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.pipeline import nodes

    monkeypatch.setattr(nodes, "RELEASE_CALL_CAP_SECONDS", 0.2)
    container = _container(_Registry({"a": _SlowHandle([readers.RUN_READER, RELEASE_JOB])}))
    _read_once(container, "a")
    began = time.monotonic()
    assert nodes.release_reader_staging(container) == []
    assert time.monotonic() - began < RELEASE_CALL_SECONDS / 2


def test_the_teardown_budget_is_one_call_s_cap_and_a_second() -> None:
    from maljan.core import container as container_module
    from maljan.pipeline import nodes

    assert nodes.RELEASE_CALL_CAP_SECONDS < container_module._RELEASE_BUDGET <= 6.0
    # The release and the synchronous sweep together stay inside the worker's 60 s cap.
    assert container_module._RELEASE_BUDGET + container_module._CLOSE_ALL_BUDGET < 60.0


def test_a_cancelled_job_still_releases() -> None:
    from maljan.agents.base_agent import run_coro_blocking
    from maljan.core.cancellation import Cancellation, JobCancelled, bound
    from maljan.pipeline import nodes

    handle = _Handle([readers.RUN_READER, RELEASE_JOB])
    container = _container(_Registry({"analysis": handle}))
    cancelled = Cancellation()
    with bound(cancelled):
        # Noted while the job ran, through the real blocking call.
        _read_once(container, "analysis")
        cancelled.cancel("the operator stopped the job")

        async def probe() -> None:
            return None

        # A call made here under the job is refused once it is cancelled ...
        with pytest.raises(JobCancelled):
            run_coro_blocking(probe(), 5.0, label="probe")
        # ... and the release, the job's teardown, is made all the same.
        assert nodes.release_reader_staging(container) == ["analysis"]
    assert handle.sent[-1] == (RELEASE_JOB, {"job": JOB}, nodes.RELEASE_SECONDS)


def test_a_server_that_declares_only_the_release_is_never_chosen_to_run_readings() -> None:
    from maljan.core.config import Settings
    from maljan.core.declared_reading import builtin_tools
    from maljan.pipeline import nodes
    from maljan.providers.servers import READER_DELIVERY_KIND, RELEASE_DELIVERY_KIND

    servers = dict(Settings(_env_file=None).mcp.servers)
    analysis = servers["analysis"]
    # What the server declares of itself, as the platform reads it.
    facts = dict(builtin_tools("analysis"))
    assert facts[RELEASE_JOB].kind == RELEASE_DELIVERY_KIND != READER_DELIVERY_KIND
    assert facts[readers.RUN_READER].kind == READER_DELIVERY_KIND
    remote = {"transport": "streamable-http", "url": "http://analysis-mcp:8098/mcp"}
    releasing_only = {name: fact for name, fact in facts.items() if name != readers.RUN_READER}
    servers["analysis"] = analysis.model_copy(update={**remote, "tool_facts": releasing_only})
    container = SimpleNamespace(
        config=SimpleNamespace(mcp=SimpleNamespace(servers=servers)),
        server_sample_paths={"analysis": "/data/samples/.work/x.exe"},
        job_key=lambda: JOB,
    )
    assert nodes.sample_readers(container, "/w/x.exe").places == {}
    # With the readers' primitive declared too, it runs them.
    servers["analysis"] = analysis.model_copy(update={**remote, "tool_facts": facts})
    container._reader_servers_held = None
    assert nodes.sample_readers(container, "/w/x.exe").place_of("pe_info") is not None


def test_a_mixed_entry_s_row_reads_as_its_least_isolated_place() -> None:
    from maljan.analysis.isolation import CHILD, IN_PROCESS, LOCAL_SERVICE, REMOTE_SERVICE
    from maljan.analysis.tool_effects import _least_isolated

    placed = {
        "pack": (IN_PROCESS, False, ""),
        "mcp:analysis": (LOCAL_SERVICE, False, ""),
        "mcp:far": (REMOTE_SERVICE, False, ""),
        "mcp:child": (CHILD, True, "measurement"),
    }
    # The worker whenever it is among them.
    assert _least_isolated(["mcp:analysis", "pack"], "pack", placed) == "pack"
    assert _least_isolated(["pack", "mcp:analysis"], "pack", placed) == "pack"
    # Otherwise not isolated before isolated, and nearest the worker first.
    assert _least_isolated(["mcp:child", "mcp:far"], "pack", placed) == "mcp:far"
    assert _least_isolated(["mcp:far", "mcp:analysis"], "pack", placed) == "mcp:analysis"
    # A place the isolation part did not place reads as nothing known.
    assert _least_isolated(["mcp:analysis", "mcp:unplaced"], "pack", placed) == "mcp:unplaced"
    assert _least_isolated([], "pack", placed) == "pack"
