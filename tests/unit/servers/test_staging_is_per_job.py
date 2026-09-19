"""Nothing one job stages is nameable by another, by the directory itself.

The bound used to be the shape of the carved tree: a payload lived under the
sha256 of the sample it came out of, so a run reached what it had carved and
nothing another run had carved. That holds two runs of the *same* sample in one
tree, leaves every ``put_sample`` upload flat in a directory every job on the
host shares, and keeps a stale tree from an old run reachable until the TTL.

The directory is the bound now. ``MALJAN_STAGING_DIR`` stays the operator's
base; the process that spawns a sidecar composes one leaf inside it per job and
hands it over as ``MALJAN_STAGING_JOB``; the sidecar joins the two. Two jobs on
two samples and two jobs on the same sample all get directories of their own,
and the job's owner takes its directory away on every way out of the run.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from maljan.tools import staging

# A live sidecar handshake plus a handful of calls. Generous, because the
# machine may be running another suite beside this one.
LIVE_BUDGET_S = 90.0

_INTERPRETER_MISSING = not sys.executable or not shutil.which(sys.executable)

live_sidecar = pytest.mark.skipif(
    _INTERPRETER_MISSING, reason="no python interpreter available to launch the sidecar"
)


class TestTheNameOneJobStagesUnder:
    def test_it_is_one_segment_whatever_the_id_was(self) -> None:
        for job_id in ("job", "../../etc", "a/b", "..", ".", "  ", "\x00x"):
            name = staging.job_directory_name(job_id)
            assert Path(name).name == name
            assert name not in (".", "..")
            assert os.sep not in name
            assert staging.is_job_directory_name(name)

    def test_two_ids_that_differ_only_in_what_is_replaced_still_differ(self) -> None:
        assert staging.job_directory_name("a/b") != staging.job_directory_name("a:b")

    def test_a_uuid_is_readable_in_it(self) -> None:
        job_id = "3f2b9c1e-0a4d-4f1b-9c2e-7d5a1b3c4e5f"
        assert staging.job_directory_name(job_id) == f"job-{job_id}"

    def test_the_same_id_always_names_the_same_directory(self) -> None:
        first = staging.job_staging_dir(Path("/base"), "one")
        assert first == staging.job_staging_dir(Path("/base"), "one")
        assert first != staging.job_staging_dir(Path("/base"), "two")

    def test_a_leaf_that_is_not_one_of_ours_is_not_joined(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The leaf comes from the parent process, and is still checked."""
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path))
        for planted in ("../elsewhere", "/etc", "carved", ""):
            monkeypatch.setenv(staging.STAGING_JOB_ENV, planted)
            assert staging.staging_root() == tmp_path


class TestTheOperatorsValueStaysTheBase:
    """``child_env`` applies ``mcp.<server>.env`` last, so the per-job value
    cannot be a path composed before it — it is a leaf composed after it."""

    @staticmethod
    def _spawn_env(name: str, job_id: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
        from maljan.core.config import Settings
        from maljan.providers.servers import ServerRegistry

        captured: dict[str, Any] = {}

        class _FakeToolkit:
            def __init__(self, server_params: Any = None, **kwargs: Any) -> None:
                captured["env"] = dict(getattr(server_params, "env", {}) or {})

            async def initialize(self) -> None:
                return None

            def get_tools(self) -> list[Any]:
                return []

        monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _FakeToolkit)
        registry = ServerRegistry(Settings(_env_file=None))
        handle = registry.get(name)
        handle.open(job_id)
        handle.close()
        return dict(captured.get("env", {}))

    def test_an_operators_staging_directory_is_not_overwritten(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "corpus-staging"))

        env = self._spawn_env("analysis", "job-a", monkeypatch)

        assert env[staging.STAGING_DIR_ENV] == str(tmp_path / "corpus-staging")
        assert env[staging.STAGING_JOB_ENV] == staging.job_directory_name("job-a")
        assert (
            staging.staging_root(env) == tmp_path / "corpus-staging" / env[staging.STAGING_JOB_ENV]
        )

    def test_a_base_nobody_configured_needs_no_spawn_side_knowledge(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The leaf alone is composed; the default base is the sidecar's own."""
        monkeypatch.delenv(staging.STAGING_DIR_ENV, raising=False)

        env = self._spawn_env("analysis", "job-b", monkeypatch)

        assert staging.STAGING_DIR_ENV not in env
        assert staging.staging_root(env) == staging.default_base() / staging.job_directory_name(
            "job-b"
        )

    def test_the_sidecar_that_stages_nothing_is_told_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The knowledge sidecar is long-lived by design and takes no path."""
        assert staging.STAGING_JOB_ENV not in self._spawn_env("knowledge", "job-c", monkeypatch)

    def test_the_capture_sidecar_is_told_the_same_leaf(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        analysis = self._spawn_env("analysis", "job-d", monkeypatch)
        network = self._spawn_env("network", "job-d", monkeypatch)

        assert network[staging.STAGING_JOB_ENV] == analysis[staging.STAGING_JOB_ENV]

    def test_a_server_of_the_operators_own_is_told_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core.config import MCPServerConfig
        from maljan.providers.servers import ServerHandle

        handle = ServerHandle(
            "theirs", MCPServerConfig(transport="stdio", command=sys.executable, args=["-c", ""])
        )
        assert handle._stages_per_job() is False

    def test_one_configured_with_the_staging_name_is(self) -> None:
        from maljan.core.config import MCPServerConfig
        from maljan.providers.servers import ServerHandle

        handle = ServerHandle(
            "theirs",
            MCPServerConfig(
                transport="stdio",
                command=sys.executable,
                args=["-c", ""],
                env_allow=[staging.STAGING_DIR_ENV],
            ),
        )
        assert handle._stages_per_job() is True


def _error(answer: Any) -> dict[str, Any]:
    parsed = json.loads(answer) if isinstance(answer, str) else answer
    assert isinstance(parsed, dict), parsed
    return parsed.get("error") or {}


def _parsed(answer: Any) -> dict[str, Any]:
    parsed = json.loads(answer) if isinstance(answer, str) else answer
    assert isinstance(parsed, dict), parsed
    return parsed


class _Job:
    """One live sidecar, attached for one job id."""

    def __init__(self, job_id: str, server: str = "analysis") -> None:
        self.job_id = job_id
        self.server = server
        self.handle: Any = None

    async def open(self) -> None:
        from maljan.core.settings_overrides import build_settings
        from maljan.providers.servers import ServerHandle

        self.handle = ServerHandle(self.server, build_settings({}).mcp.servers[self.server])
        await self.handle.aopen(self.job_id)

    async def call(self, tool: str, **kwargs: Any) -> Any:
        tools = {str(getattr(t, "name", "")): t for t in self.handle.tools()}
        return await tools[tool].ainvoke(kwargs)

    async def close(self) -> None:
        if self.handle is not None:
            await self.handle.aclose()

    @property
    def directory(self) -> Path:
        return staging.job_directories(self.job_id)[0]


def _dropper(target: Path, marker: bytes) -> Path:
    """A file the carver finds one embedded payload in."""
    target.write_bytes(b"DECOY\x00" + b"MZ\x90\x00" + b"\x00" * 2048 + marker)
    return target


@pytest.fixture(autouse=True)
def _no_directories_from_another_test() -> Any:
    """What this test's spawns compose is this test's, and goes with it.

    A job id is unique per run in production; two tests in one session are not,
    so the record of what was composed is emptied around each of them rather
    than letting one test's directory be removed by another's teardown.
    """
    kept = dict(staging._COMPOSED)
    staging._COMPOSED.clear()
    yield
    staging._COMPOSED.clear()
    staging._COMPOSED.update(kept)


@pytest.fixture
def samples(tmp_path: Path) -> Path:
    """The deployment's sample directory, which the staging base is not in."""
    directory = tmp_path / "samples"
    directory.mkdir()
    return directory


@pytest.fixture
def staged(tmp_path: Path, samples: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A private staging base and a sample root, for the live sidecars below."""
    from maljan.tools.roots import SAMPLE_ROOTS_ENV

    base = tmp_path / "staging"
    monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
    monkeypatch.setenv(SAMPLE_ROOTS_ENV, str(samples))
    monkeypatch.delenv(staging.STAGING_JOB_ENV, raising=False)
    return base


@live_sidecar
class TestTwoLiveJobsCannotNameEachOthersFiles:
    """The proof the shape is meant to give, through real sidecar processes."""

    @staticmethod
    def _run(coro: Any) -> Any:
        return asyncio.run(asyncio.wait_for(coro, timeout=LIVE_BUDGET_S))

    def test_two_jobs_on_two_samples(self, staged: Path, samples: Path) -> None:
        mine = _dropper(samples / "a.bin", b"PAYLOAD-OF-A\x00")
        theirs = _dropper(samples / "b.bin", b"PAYLOAD-OF-B\x00")

        async def two_jobs() -> tuple[Any, Any, Any]:
            first, second = _Job("one"), _Job("two")
            await first.open()
            await second.open()
            try:
                ours = _parsed(await first.call("carve_payloads", path=str(mine)))
                yours = _parsed(await second.call("carve_payloads", path=str(theirs)))
                assert ours["count"] >= 1 and yours["count"] >= 1, (ours, yours)
                stolen = await first.call(
                    "strings",
                    path=str(mine),
                    carved_path=yours["payloads"][0]["path"],
                    min_len=6,
                )
                return ours, yours, stolen
            finally:
                await first.close()
                await second.close()

        ours, yours, stolen = self._run(two_jobs())

        first_dir = staging.job_staging_dir(staged, "one")
        second_dir = staging.job_staging_dir(staged, "two")
        assert first_dir != second_dir
        assert first_dir in Path(ours["payloads"][0]["path"]).parents
        assert second_dir in Path(yours["payloads"][0]["path"]).parents
        assert _error(stolen).get("code") == "path_outside_roots"

    def test_two_jobs_on_the_same_sample(self, staged: Path, samples: Path) -> None:
        """The case the carved-tree bound could not answer: one sample, one
        digest, one tree — and now two directories."""
        sample = _dropper(samples / "shared.bin", b"PAYLOAD-SHARED\x00")

        async def two_jobs() -> tuple[Any, Any, Any, list[Any]]:
            first, second = _Job("one"), _Job("two")
            await first.open()
            await second.open()
            try:
                ours = _parsed(await first.call("carve_payloads", path=str(sample)))
                yours = _parsed(await second.call("carve_payloads", path=str(sample)))
                assert ours["count"] >= 1 and yours["count"] >= 1, (ours, yours)
                theirs = Path(yours["payloads"][0]["path"])
                spellings = [
                    str(theirs),
                    str(theirs.relative_to(staging.job_staging_dir(staged, "two"))),
                    f"../{staging.job_directory_name('two')}/{theirs.name}",
                    yours["payloads"][0]["name"],
                ]
                refusals = [
                    await first.call("strings", path=str(sample), carved_path=spelling, min_len=6)
                    for spelling in spellings
                ]
                mine = await first.call(
                    "strings",
                    path=str(sample),
                    carved_path=ours["payloads"][0]["path"],
                    min_len=6,
                )
                return ours, yours, mine, refusals
            finally:
                await first.close()
                await second.close()

        ours, yours, mine, answers = self._run(two_jobs())

        mine_path = Path(ours["payloads"][0]["path"])
        theirs_path = yours["payloads"][0]["path"]
        assert mine_path.is_relative_to(staging.job_staging_dir(staged, "one"))
        assert Path(theirs_path).is_relative_to(staging.job_staging_dir(staged, "two"))
        assert _parsed(mine)["read_path"] == str(mine_path)
        # The absolute path and the climb into the other directory are refused
        # outright. The bare tail and the display label are not the other job's
        # file at all: both jobs carved the same bytes, so each spelling names
        # the copy in the job's own tree — which is what the directory boundary
        # means. Either way, nothing answers with the other job's path.
        for answer in answers:
            parsed = _parsed(answer)
            read = parsed.get("read_path")
            if read is None:
                assert parsed["error"]["code"] in ("path_outside_roots", "no_such_file"), answer
                continue
            assert Path(read).is_relative_to(staging.job_staging_dir(staged, "one")), answer
            assert read != theirs_path, answer

    def test_an_upload_is_not_reachable_from_another_job(self, staged: Path, samples: Path) -> None:
        import base64
        import hashlib

        blob = b"AN-OPERATORS-OWN-DOCUMENT\x00"
        sample = _dropper(samples / "a.bin", b"PAYLOAD-OF-A\x00")

        async def two_jobs() -> tuple[Any, Any]:
            first, second = _Job("one"), _Job("two")
            await first.open()
            await second.open()
            try:
                uploaded = _parsed(
                    await second.call(
                        "put_sample",
                        filename="theirs.doc",
                        content_b64=base64.b64encode(blob).decode("ascii"),
                        sha256=hashlib.sha256(blob).hexdigest(),
                    )
                )
                read = await first.call("strings", path=uploaded["path"], min_len=6)
                carved = await first.call(
                    "strings", path=str(sample), carved_path=uploaded["path"], min_len=6
                )
                return read, carved
            finally:
                await first.close()
                await second.close()

        read, carved = self._run(two_jobs())

        assert _error(read).get("code") == "path_outside_roots"
        assert _error(carved).get("code") == "path_outside_roots"

    def test_a_job_reads_its_own_upload(self, staged: Path) -> None:
        import base64
        import hashlib

        blob = b"MY-OWN-UPLOAD-CONTENT\x00"

        async def one_job() -> tuple[Any, Any]:
            job = _Job("one")
            await job.open()
            try:
                uploaded = _parsed(
                    await job.call(
                        "put_sample",
                        filename="mine.bin",
                        content_b64=base64.b64encode(blob).decode("ascii"),
                        sha256=hashlib.sha256(blob).hexdigest(),
                    )
                )
                return uploaded, await job.call("strings", path=uploaded["path"], min_len=6)
            finally:
                await job.close()

        uploaded, read = self._run(one_job())

        assert Path(uploaded["path"]).parent == staging.job_staging_dir(staged, "one")
        assert _error(read) == {}
        assert [row["text"] for row in _parsed(read)["strings"]] == ["MY-OWN-UPLOAD-CONTENT"]

    def test_a_finished_jobs_directory_is_gone(self, staged: Path, samples: Path) -> None:
        """The removal the worker makes, on the path the worker makes it."""
        from app.worker.analysis_worker import remove_job_staging

        sample = _dropper(samples / "a.bin", b"PAYLOAD-OF-A\x00")

        async def one_job() -> Any:
            job = _Job("one")
            await job.open()
            try:
                return _parsed(await job.call("carve_payloads", path=str(sample)))
            finally:
                await job.close()

        carved = self._run(one_job())
        directory = staging.job_staging_dir(staged, "one")
        assert directory.is_dir() and Path(carved["payloads"][0]["path"]).exists()

        removed = remove_job_staging("one")

        assert removed == [directory]
        assert not directory.exists()
        assert staged.is_dir(), "the base an operator configured stays"
        assert staging.job_directories("one") == []


class TestTheSweepReachesAJobDirectory:
    """Item three of the four: the walk used to skip directories, and with
    everything a level deeper it would have stopped pruning entirely."""

    @staticmethod
    def _server() -> Any:
        import importlib.util

        root = Path(__file__).resolve().parents[3]
        spec = importlib.util.spec_from_file_location(
            "analysis_mcp_server_per_job", root / "services" / "analysis-mcp" / "server.py"
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def _aged(path: Path, seconds_ago: float) -> None:
        when = time.time() - seconds_ago
        os.utime(path, (when, when))

    def test_a_stale_job_directory_goes_whole(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = self._server()
        base = tmp_path / "staging"
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
        monkeypatch.setenv(staging.STAGING_TTL_ENV, "1")
        directory = staging.job_staging_dir(base, "old")
        tree = directory / "carved" / ("a" * 64)
        tree.mkdir(parents=True)
        payload = tree / "payload_0.bin"
        payload.write_bytes(b"OLD\x00")
        upload = directory / "aaaaaaaaaaaaaaaa_old.exe"
        upload.write_bytes(b"OLD-UPLOAD\x00")
        for entry in (payload, upload, tree, tree.parent, directory):
            self._aged(entry, 7200)

        removed = server._prune_staging(base)

        assert removed == 2
        assert not directory.exists()

    def test_a_live_jobs_directory_stays_and_is_swept_inside(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = self._server()
        base = tmp_path / "staging"
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
        monkeypatch.setenv(staging.STAGING_TTL_ENV, "1")
        directory = staging.job_staging_dir(base, "live")
        tree = directory / "carved" / ("b" * 64)
        tree.mkdir(parents=True)
        stale = tree / "payload_0.bin"
        stale.write_bytes(b"OLD\x00")
        self._aged(stale, 7200)
        fresh = directory / "bbbbbbbbbbbbbbbb_new.exe"
        fresh.write_bytes(b"NEW\x00")

        removed = server._prune_staging(base)

        assert removed == 1
        assert directory.is_dir() and fresh.exists()
        assert not stale.exists()

    def test_the_newest_mtime_inside_decides_and_a_link_is_not_followed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = self._server()
        base = tmp_path / "staging"
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
        monkeypatch.setenv(staging.STAGING_TTL_ENV, "1")
        outside = tmp_path / "not-staging.txt"
        outside.write_bytes(b"SOMEBODY-ELSES\x00")
        directory = staging.job_staging_dir(base, "linked")
        directory.mkdir(parents=True)
        (directory / "pointer").symlink_to(outside)
        self._aged(directory, 7200)
        os.utime(directory / "pointer", (time.time() - 7200,) * 2, follow_symlinks=False)

        server._prune_staging(base)

        assert not directory.exists(), "a stale job directory goes with the links in it"
        assert outside.exists(), "and what a link pointed at is somebody else's"

    def test_the_flat_files_of_the_release_before_are_still_swept(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The upgrade note's claim: nothing to migrate, the TTL takes them."""
        server = self._server()
        base = tmp_path / "staging"
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
        monkeypatch.setenv(staging.STAGING_TTL_ENV, "1")
        base.mkdir(parents=True)
        old = base / "cccccccccccccccc_flat.exe"
        old.write_bytes(b"FROM-THE-OLD-LAYOUT\x00")
        self._aged(old, 7200)
        old_tree = base / "carved" / ("c" * 64)
        old_tree.mkdir(parents=True)
        old_payload = old_tree / "payload_0.bin"
        old_payload.write_bytes(b"OLD\x00")
        self._aged(old_payload, 7200)

        assert server._prune_staging(base) == 2
        assert not old.exists() and not old_payload.exists()

    def test_a_disabled_ttl_reaches_no_job_directory_either(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = self._server()
        base = tmp_path / "staging"
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
        monkeypatch.setenv(staging.STAGING_TTL_ENV, "0")
        directory = staging.job_staging_dir(base, "old")
        directory.mkdir(parents=True)
        stale = directory / "dddddddddddddddd_old.exe"
        stale.write_bytes(b"OLD\x00")
        self._aged(stale, 999999)
        self._aged(directory, 999999)

        assert server._prune_staging(base) == 0
        assert stale.exists()


class TestRemovingADirectoryOfMalware:
    def test_a_link_inside_it_is_unlinked_and_never_followed(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "keep.txt").write_bytes(b"NOT-THIS\x00")
        directory = tmp_path / "job-one"
        (directory / "carved" / "abc").mkdir(parents=True)
        (directory / "carved" / "abc" / "payload").write_bytes(b"PAYLOAD\x00")
        (directory / "pointer").symlink_to(outside)

        assert staging.remove_tree(directory) is True
        assert not directory.exists()
        assert (outside / "keep.txt").exists()

    def test_nothing_readable_is_left_behind(self, tmp_path: Path) -> None:
        directory = tmp_path / "job-one"
        inner = directory / "carved" / "abc"
        inner.mkdir(parents=True)
        (inner / "payload").write_bytes(b"PAYLOAD\x00")
        inner.chmod(0o755)

        assert staging.remove_tree(directory) is True
        assert not directory.exists()

    def test_a_base_of_somebody_elses_is_refused_before_anything_is_written(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ownership check the base always had now guards the job dir too."""
        server = TestTheSweepReachesAJobDirectory._server()
        base = tmp_path / "staging"
        base.mkdir()
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
        monkeypatch.setenv(staging.STAGING_JOB_ENV, staging.job_directory_name("one"))
        directory = staging.job_staging_dir(base, "one")
        directory.mkdir()
        directory.chmod(0o777)

        assert Path(server._staging_dir()) == directory
        assert stat.S_IMODE(directory.lstat().st_mode) == 0o700

    def test_a_job_directory_that_is_a_symlink_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = TestTheSweepReachesAJobDirectory._server()
        base = tmp_path / "staging"
        base.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
        monkeypatch.setenv(staging.STAGING_JOB_ENV, staging.job_directory_name("one"))
        staging.job_staging_dir(base, "one").symlink_to(elsewhere)

        with pytest.raises(RuntimeError, match="symlink"):
            server._staging_dir()


class TestTheStagedPathCacheBelongsToItsJob:
    """Item two of the four: a process-wide key hands the next job a path
    inside a directory the last job's teardown removed."""

    def test_two_jobs_on_one_sample_stage_twice(self, tmp_path: Path) -> None:
        from maljan.agents import sample_staging

        sample_staging.clear_cache()
        calls: list[str] = []

        class _Tool:
            name = "put_sample"

            async def ainvoke(self, kwargs: dict[str, Any]) -> Any:
                calls.append(kwargs["sha256"])
                return {"path": f"/staging/job-{len(calls)}/x.bin"}

        class _Handle:
            is_open = True
            config = type("C", (), {"transport": "http"})()

            def all_tool_names(self) -> list[str]:
                return ["put_sample"]

            def tools(self) -> list[Any]:
                return [_Tool()]

        class _Registry:
            degradation_reasons: list[str] = []

            def get(self, key: str) -> Any:
                return _Handle()

        sample = tmp_path / "s.bin"
        sample.write_bytes(b"SAMPLE\x00")
        import hashlib

        digest = hashlib.sha256(sample.read_bytes()).hexdigest()

        async def stage(job_id: str) -> Any:
            return await sample_staging.stage_sample(
                _Registry(), "remote", str(sample), sha256=digest, job_id=job_id
            )

        first = asyncio.run(stage("one"))
        again = asyncio.run(stage("one"))
        second = asyncio.run(stage("two"))

        assert first == again, "one job still uploads a sample once"
        assert second != first, "another job is not handed the first job's path"
        assert len(calls) == 2
        sample_staging.clear_cache()

    def test_a_finished_jobs_entries_go(self, tmp_path: Path) -> None:
        from maljan.agents import sample_staging

        sample_staging.clear_cache()
        now = time.monotonic()
        sample_staging._CACHE[("one", "remote", "a" * 64)] = ("/staging/job-one/x", now)
        sample_staging._CACHE[("two", "remote", "a" * 64)] = ("/staging/job-two/x", now)

        assert sample_staging.forget_job("one") == 1
        assert list(sample_staging._CACHE) == [("two", "remote", "a" * 64)]
        sample_staging.clear_cache()

    def test_the_worker_forgets_them_where_it_removes_the_directory(self, tmp_path: Path) -> None:
        from app.worker.analysis_worker import remove_job_staging
        from maljan.agents import sample_staging

        sample_staging.clear_cache()
        sample_staging._CACHE[("one", "analysis", "b" * 64)] = ("/gone/x", time.monotonic())
        directory = tmp_path / staging.job_directory_name("one")
        directory.mkdir()
        (directory / "upload.bin").write_bytes(b"BYTES\x00")
        staging.note_job_directory("one", directory)

        assert remove_job_staging("one") == [directory]
        assert not directory.exists()
        assert sample_staging._CACHE == {}

    def test_a_job_that_staged_nothing_removes_nothing(self) -> None:
        from app.worker.analysis_worker import remove_job_staging

        assert remove_job_staging("a-job-that-never-ran") == []


class TestTheBoundaryWhenTheBaseIsInsideASampleRoot:
    """The configuration ``confined_to_this_job`` exists for.

    A deployment may put its staging base inside the directory it keeps samples
    in, and then a sibling job's directory answers the roots question
    truthfully: it really is inside a root this server may read. The job
    directory is the boundary whatever the roots are.
    """

    @pytest.fixture
    def nested(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        from maljan.tools.roots import SAMPLE_ROOTS_ENV

        corpus = tmp_path / "corpus"
        base = corpus / "staging"
        base.mkdir(parents=True)
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
        monkeypatch.setenv(SAMPLE_ROOTS_ENV, str(corpus))
        monkeypatch.setenv(staging.STAGING_JOB_ENV, staging.job_directory_name("mine"))
        return base

    def test_a_sibling_jobs_file_is_refused(self, nested: Path) -> None:
        from maljan.tools.roots import PathOutsideRoots, resolve_under_roots

        theirs = staging.job_staging_dir(nested, "theirs")
        theirs.mkdir()
        (theirs / "upload.bin").write_bytes(b"THEIRS\x00")
        inside = resolve_under_roots(str(theirs / "upload.bin"))

        with pytest.raises(PathOutsideRoots):
            staging.confined_to_this_job(inside)

    def test_this_jobs_own_file_is_not(self, nested: Path) -> None:
        from maljan.tools.roots import resolve_under_roots

        mine = staging.job_staging_dir(nested, "mine")
        (mine / "carved").mkdir(parents=True)
        (mine / "carved" / "payload").write_bytes(b"MINE\x00")
        inside = resolve_under_roots(str(mine / "carved" / "payload"))

        assert staging.confined_to_this_job(inside) == inside

    def test_a_sample_outside_the_base_is_not_touched(self, nested: Path, tmp_path: Path) -> None:
        from maljan.tools.roots import resolve_under_roots

        sample = tmp_path / "corpus" / "sample.bin"
        sample.write_bytes(b"SAMPLE\x00")
        inside = resolve_under_roots(str(sample))

        assert staging.confined_to_this_job(inside) == inside

    def test_a_server_with_no_leaf_is_held_to_nothing_new(
        self, nested: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A probe or a hand-started server writes in the base itself."""
        from maljan.tools.roots import resolve_under_roots

        monkeypatch.delenv(staging.STAGING_JOB_ENV, raising=False)
        theirs = staging.job_staging_dir(nested, "theirs")
        theirs.mkdir()
        (theirs / "upload.bin").write_bytes(b"THEIRS\x00")
        inside = resolve_under_roots(str(theirs / "upload.bin"))

        assert staging.confined_to_this_job(inside) == inside


class TestTheLeafIsTheSpawnsAlone:
    def test_a_stored_mapping_cannot_supply_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``child_env`` applies a server's own map last, so the composed name
        is cleared before the question of composing one is even asked."""
        from maljan.core.config import MCPServerConfig
        from maljan.providers.servers import ServerHandle

        captured: dict[str, Any] = {}

        class _FakeToolkit:
            def __init__(self, server_params: Any = None, **kwargs: Any) -> None:
                captured["env"] = dict(getattr(server_params, "env", {}) or {})

            async def initialize(self) -> None:
                return None

            def get_tools(self) -> list[Any]:
                return []

        monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _FakeToolkit)
        config = MCPServerConfig.model_construct(
            enabled=True,
            transport="stdio",
            command=sys.executable,
            args=["-c", ""],
            env={staging.STAGING_JOB_ENV: staging.job_directory_name("someone-else")},
            env_allow=[],
            tools=None,
            agents=[],
            label="",
            cwd="",
            url="",
        )
        handle = ServerHandle("theirs", config)
        handle.open("mine")
        handle.close()

        assert staging.STAGING_JOB_ENV not in captured["env"]

    def test_a_staging_server_gets_the_spawns_name_and_not_the_stored_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core.config import MCPServerConfig
        from maljan.providers.servers import ServerHandle

        captured: dict[str, Any] = {}

        class _FakeToolkit:
            def __init__(self, server_params: Any = None, **kwargs: Any) -> None:
                captured["env"] = dict(getattr(server_params, "env", {}) or {})

            async def initialize(self) -> None:
                return None

            def get_tools(self) -> list[Any]:
                return []

        monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _FakeToolkit)
        config = MCPServerConfig.model_construct(
            enabled=True,
            transport="stdio",
            command=sys.executable,
            args=["-c", ""],
            env={staging.STAGING_JOB_ENV: staging.job_directory_name("someone-else")},
            env_allow=[staging.STAGING_DIR_ENV],
            tools=None,
            agents=[],
            label="",
            cwd="",
            url="",
        )
        handle = ServerHandle("theirs", config)
        handle.open("mine")
        handle.close()

        assert captured["env"][staging.STAGING_JOB_ENV] == staging.job_directory_name("mine")

    def test_settings_refuse_the_name_where_it_is_entered(self) -> None:
        import pydantic

        from maljan.core.config import MCPServerConfig

        for field in ("env", "env_allow"):
            payload: dict[str, Any] = {"transport": "stdio", "command": "/bin/true"}
            payload[field] = (
                {staging.STAGING_JOB_ENV: "job-x"} if field == "env" else [staging.STAGING_JOB_ENV]
            )
            with pytest.raises(pydantic.ValidationError, match=staging.STAGING_JOB_ENV):
                MCPServerConfig(**payload)


class TestAHandleOpensUnderTheJobsIdentity:
    def test_a_static_provider_names_the_job_and_not_the_sample(self) -> None:
        """Two jobs on one sample are the case a per-job directory exists for,
        and the sample's digest is the same string for both of them."""
        from maljan.core.config import MCPServerConfig
        from maljan.providers.base import StaticJobContext
        from maljan.providers.static.generic_mcp import GenericMCPStaticProvider

        opened: list[str] = []

        class _Provider(GenericMCPStaticProvider):
            pass

        provider = _Provider(
            MCPServerConfig(transport="stdio", command="/bin/true"), label="generic"
        )
        provider._handle.open = lambda job_id, **_k: opened.append(job_id)  # type: ignore[method-assign]
        provider._handle.tools = lambda: []  # type: ignore[method-assign]

        provider.open(StaticJobContext(job_key="job-one", sha256="d" * 64))

        assert opened == ["job-one"]

    def test_with_no_job_it_still_has_an_identity_of_its_own(self) -> None:
        from maljan.core.config import MCPServerConfig
        from maljan.providers.base import StaticJobContext
        from maljan.providers.static.generic_mcp import GenericMCPStaticProvider

        opened: list[str] = []
        provider = GenericMCPStaticProvider(
            MCPServerConfig(transport="stdio", command="/bin/true"), label="generic"
        )
        provider._handle.open = lambda job_id, **_k: opened.append(job_id)  # type: ignore[method-assign]
        provider._handle.tools = lambda: []  # type: ignore[method-assign]

        provider.open(StaticJobContext(sha256="e" * 64))

        assert opened == ["e" * 64]

    def test_the_resolver_hands_the_provider_the_containers_job(self) -> None:
        import inspect

        from maljan.agents import composition

        source = inspect.getsource(composition._provider_tools)
        assert "job_key=container.job_key()" in source


class TestALiveJobKeepsItsDirectory:
    """A sidecar sweeping the shared base cannot ask whether a job is alive, so
    the job says so on disk."""

    def test_the_owner_keeps_the_directory_current(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "staging"))
        directory = staging.job_staging_dir(tmp_path / "staging", "live")
        directory.mkdir(parents=True)
        staging.note_job_directory("live", directory)
        long_ago = time.time() - 7200
        os.utime(directory, (long_ago, long_ago))

        assert staging.touch_job_staging("live") is True
        assert directory.lstat().st_mtime > long_ago + 3000

    def test_a_job_that_staged_nothing_has_nothing_to_touch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "staging"))

        assert staging.touch_job_staging("never") is False

    def test_it_touches_what_the_spawn_recorded_and_not_the_workers_own_base(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An operator may set the base in a server's own ``env`` map alone,
        and then the directory the sidecar sweeps is not the one this process
        would compute for itself. The marker has to reach the swept one."""
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "the-workers-base"))
        theirs = staging.job_staging_dir(tmp_path / "the-servers-base", "split")
        theirs.mkdir(parents=True)
        staging.note_job_directory("split", theirs)
        long_ago = time.time() - 7200
        os.utime(theirs, (long_ago, long_ago))

        assert staging.touch_job_staging("split") is True
        assert theirs.lstat().st_mtime > long_ago + 3000
        assert not staging.job_staging_dir(tmp_path / "the-workers-base", "split").exists()

    def test_a_touched_directory_survives_another_workers_sweep(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = TestTheSweepReachesAJobDirectory._server()
        base = tmp_path / "staging"
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
        monkeypatch.setenv(staging.STAGING_TTL_ENV, "1")
        directory = staging.job_staging_dir(base, "long-run")
        directory.mkdir(parents=True)
        staging.note_job_directory("long-run", directory)
        stale = directory / "ffffffffffffffff_old.exe"
        stale.write_bytes(b"STAGED-AT-THE-START\x00")
        long_ago = time.time() - 7200
        for entry in (stale, directory):
            os.utime(entry, (long_ago, long_ago))

        staging.touch_job_staging("long-run")
        server._prune_staging(base)

        assert directory.is_dir(), "the job said it was still running"


class TestTheBaseIsRecordedAbsolute:
    def test_a_relative_setting_is_made_absolute_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The worker resolves a relative value against its own directory and a
        built-in sidecar against the one it is spawned with."""
        monkeypatch.setenv(staging.STAGING_DIR_ENV, "rel/staging")

        assert staging.staging_base().is_absolute()
        assert staging.job_staging_dir(staging.staging_base(), "one").is_absolute()

    def test_what_the_spawn_records_is_absolute(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from maljan.core.config import MCPServerConfig
        from maljan.providers.servers import ServerHandle

        class _FakeToolkit:
            def __init__(self, server_params: Any = None, **kwargs: Any) -> None:
                pass

            async def initialize(self) -> None:
                return None

            def get_tools(self) -> list[Any]:
                return []

        monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _FakeToolkit)
        monkeypatch.setenv(staging.STAGING_DIR_ENV, "rel/staging")
        handle = ServerHandle(
            "analysis",
            MCPServerConfig(
                transport="stdio",
                command=sys.executable,
                args=["-c", ""],
                env_allow=[staging.STAGING_DIR_ENV],
            ),
        )
        handle.open("rel-job")
        handle.close()

        assert all(path.is_absolute() for path in staging.job_directories("rel-job"))


class TestAMissingDirectoryIsNotARemoval:
    def test_it_is_not_counted(self, tmp_path: Path) -> None:
        staging.note_job_directory("never-staged", tmp_path / "job-never-staged")

        assert staging.remove_job_staging("never-staged") == []

    def test_one_that_was_there_is(self, tmp_path: Path) -> None:
        directory = tmp_path / "job-real"
        directory.mkdir()
        (directory / "upload.bin").write_bytes(b"BYTES\x00")
        staging.note_job_directory("real", directory)

        assert staging.remove_job_staging("real") == [directory]


# A libpcap file with a global header and no packets: enough for a reader to
# open it and report nothing, which is all these tests ask of one.
EMPTY_CAPTURE = bytes.fromhex("d4c3b2a1020004000000000000000000000004000100000000")[:24]


class TestASandboxCaptureBelongsToItsJob:
    """A capture is the one file the platform writes into staging without
    going through ``put_sample``, and ``pcap_path`` is a qualified argument the
    *model* writes — read out of the prompt the network analyst was given. It
    used to land in one directory shared by every job on the host, named as a
    permanent sample root and removed by nothing."""

    def test_it_lands_in_this_jobs_own_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.tools.roots import ROOT_SEPARATOR, SAMPLE_ROOTS_ENV

        base = tmp_path / "staging"
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
        monkeypatch.setenv(SAMPLE_ROOTS_ENV, "")

        captures = staging.open_capture_dir("one")

        assert captures == staging.job_staging_dir(base, "one") / "captures"
        assert captures.is_dir()
        for directory in (base, captures.parent, captures):
            assert stat.S_IMODE(directory.lstat().st_mode) == 0o700
        roots = os.environ[SAMPLE_ROOTS_ENV].split(ROOT_SEPARATOR)
        assert str(captures) in roots, "this job's sidecars may read it"

    def test_a_streamed_capture_is_not_left_readable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A provider writes it through an HTTP client at the process umask."""
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "staging"))
        captures = staging.open_capture_dir("one")
        written = captures / "rest_41.pcap"
        written.write_bytes(EMPTY_CAPTURE)
        written.chmod(0o664)

        staging.make_private(written)

        assert stat.S_IMODE(written.lstat().st_mode) == 0o600

    def test_the_root_and_the_directory_go_when_the_job_does(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.tools.roots import SAMPLE_ROOTS_ENV

        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "staging"))
        monkeypatch.setenv(SAMPLE_ROOTS_ENV, "")
        captures = staging.open_capture_dir("one")
        (captures / "rest_41.pcap").write_bytes(EMPTY_CAPTURE)

        removed = staging.remove_job_staging("one")

        assert removed == [captures.parent]
        assert not captures.exists()
        assert str(captures) not in os.environ[SAMPLE_ROOTS_ENV]

    def test_a_later_job_does_not_inherit_the_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The permanent root of the release before this is what let a later
        job's sidecars read an earlier job's capture."""
        from maljan.tools.roots import SAMPLE_ROOTS_ENV, configured_roots

        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "staging"))
        monkeypatch.setenv(SAMPLE_ROOTS_ENV, "")
        first = staging.open_capture_dir("one")
        staging.remove_job_staging("one")

        second = staging.open_capture_dir("two")

        assert first not in configured_roots()
        assert second in configured_roots()
        staging.remove_job_staging("two")

    def test_the_sweep_takes_the_directory_the_old_release_left(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = TestTheSweepReachesAJobDirectory._server()
        base = tmp_path / "staging"
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
        monkeypatch.setenv(staging.STAGING_TTL_ENV, "1")
        monkeypatch.setattr(server.tempfile, "gettempdir", lambda: str(tmp_path))
        legacy = tmp_path / staging.LEGACY_CAPTURE_DIR_NAME
        legacy.mkdir()
        old = legacy / "rest_41.pcap"
        old.write_bytes(EMPTY_CAPTURE)
        long_ago = time.time() - 7200
        os.utime(old, (long_ago, long_ago))
        elsewhere = tmp_path / "somebody-elses.pcap"
        elsewhere.write_bytes(EMPTY_CAPTURE)
        (legacy / "pointer.pcap").symlink_to(elsewhere)
        os.utime(legacy / "pointer.pcap", (long_ago, long_ago), follow_symlinks=False)
        base.mkdir(parents=True, exist_ok=True)

        removed = server._prune_staging(base)

        assert removed == 1
        assert not old.exists()
        assert elsewhere.exists(), "a link is never followed out of it"

    def test_a_fresh_capture_in_the_old_directory_stays(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = TestTheSweepReachesAJobDirectory._server()
        base = tmp_path / "staging"
        base.mkdir(parents=True)
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
        monkeypatch.setenv(staging.STAGING_TTL_ENV, "1")
        monkeypatch.setattr(server.tempfile, "gettempdir", lambda: str(tmp_path))
        legacy = tmp_path / staging.LEGACY_CAPTURE_DIR_NAME
        legacy.mkdir()
        fresh = legacy / "rest_42.pcap"
        fresh.write_bytes(EMPTY_CAPTURE)

        assert server._prune_staging(base) == 0
        assert fresh.exists()

    def test_the_shared_directory_is_no_longer_written(self) -> None:
        """Nothing composes the old path any more; the sweep names it, and the
        one place it is named is the sweep."""
        root = Path(__file__).resolve().parents[3]
        written = [
            path
            for path in (root / "src" / "maljan").rglob("*.py")
            if staging.LEGACY_CAPTURE_DIR_NAME in path.read_text(encoding="utf-8")
        ]

        assert [path.name for path in written] == ["staging.py"]


@live_sidecar
class TestNoJobCanNameAnotherJobsCapture:
    """The proof, through live children of both file-reading sidecars."""

    @staticmethod
    def _run(coro: Any) -> Any:
        return asyncio.run(asyncio.wait_for(coro, timeout=LIVE_BUDGET_S))

    @pytest.fixture
    def two_captures(self, staged: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
        """One capture per job, each in its job's own directory, both named as
        roots — the second half being the configuration this has to hold under
        even when a root points straight at the other job's directory."""
        from maljan.tools.roots import add_sample_root

        mine = staging.open_capture_dir("one") / "rest_41.pcap"
        theirs = staging.open_capture_dir("two") / "rest_42.pcap"
        for capture in (mine, theirs):
            capture.write_bytes(EMPTY_CAPTURE)
            staging.make_private(capture)
        add_sample_root(theirs.parent)
        return mine, theirs

    def test_the_capture_sidecar_refuses_every_spelling(
        self, staged: Path, two_captures: tuple[Path, Path]
    ) -> None:
        mine, theirs = two_captures

        async def one_job() -> tuple[list[Any], Any]:
            job = _Job("one", server="network")
            await job.open()
            try:
                root = staging.job_staging_dir(staged, "one") / "captures"
                spellings = [
                    str(theirs),
                    os.path.relpath(theirs, root),
                    f"../../{staging.job_directory_name('two')}/captures/{theirs.name}",
                    str(theirs.parent),
                ]
                refused = [
                    await job.call("read_pcap_summary", pcap_path=spelling)
                    for spelling in spellings
                ]
                return refused, await job.call("read_pcap_summary", pcap_path=str(mine))
            finally:
                await job.close()

        refused, own = self._run(one_job())

        for answer in refused:
            assert _error(answer).get("code") == "path_outside_roots", answer
        # This tool answers in prose rather than JSON when it reads one, so
        # "not a refusal" is what says the job reaches its own capture.
        assert "path_outside_roots" not in str(own), own

    def test_the_analysis_sidecar_refuses_it_too(
        self, staged: Path, two_captures: tuple[Path, Path]
    ) -> None:
        mine, theirs = two_captures

        async def one_job() -> tuple[Any, Any]:
            job = _Job("one")
            await job.open()
            try:
                return (
                    await job.call("identify_file", path=str(theirs)),
                    await job.call("identify_file", path=str(mine)),
                )
            finally:
                await job.close()

        stolen, own = self._run(one_job())

        assert _error(stolen).get("code") == "path_outside_roots"
        assert _error(own) == {}


class TestTheSidecarThatStagesNothingIsUnaffected:
    """The knowledge sidecar is long-lived by design and takes no path
    argument, so it gets no job directory — and it now has an environment name
    of its own, which must not be read as a reason to give it one."""

    def test_its_required_name_is_not_a_staging_one(self) -> None:
        from maljan.core.config import REQUIRED_ENV_ALLOW, Settings
        from maljan.providers.servers import ServerHandle

        settings = Settings(_env_file=None)
        handle = ServerHandle("knowledge", settings.mcp.servers["knowledge"])

        assert REQUIRED_ENV_ALLOW.get("knowledge")
        assert staging.STAGING_DIR_ENV not in REQUIRED_ENV_ALLOW["knowledge"]
        assert handle._stages_per_job() is False

    def test_what_it_does_need_still_reaches_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from maljan.agents.subprocess_env import child_env
        from maljan.core.config import Settings
        from maljan.providers.servers import ServerHandle

        monkeypatch.setenv("MALJAN_INDEX_RETRY_SECONDS", "900")
        handle = ServerHandle("knowledge", Settings(_env_file=None).mcp.servers["knowledge"])
        handle._job_id = "job-x"
        env = child_env(handle.config.env, allow=tuple(handle.config.env_allow))

        handle._name_the_job_staging(env)

        assert env["MALJAN_INDEX_RETRY_SECONDS"] == "900"
        assert staging.STAGING_JOB_ENV not in env


class TestARunWithNoJobIdEndsLikeOne:
    """The command line has no worker behind it, so its own teardown is the
    only thing between a finished run and a directory of live malware."""

    def test_the_key_is_per_run_and_a_recycled_pid_inherits_nothing(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        first = ServiceContainer(Settings(_env_file=None), mock=True)
        second = ServiceContainer(Settings(_env_file=None), mock=True)

        assert first.job_key() != second.job_key()
        assert staging.job_directory_name(first.job_key()) != staging.job_directory_name(
            second.job_key()
        )

    def test_the_container_takes_its_staging_with_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "staging"))
        container = ServiceContainer(Settings(_env_file=None), mock=True)
        captures = staging.open_capture_dir(container.job_key())
        (captures / "rest_1.pcap").write_bytes(EMPTY_CAPTURE)
        directory = captures.parent

        asyncio.run(container.aclose())

        assert not directory.exists()

    def test_the_command_line_releases_its_run_on_every_way_out(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Driven through the command's own entry function, with the pipeline
        replaced: what is under test is the ``finally``, not the analysis."""
        import typer

        from maljan import cli

        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "staging"))
        released: list[str] = []
        made: list[Any] = []
        ending: list[BaseException] = []

        class _App:
            def __init__(self, **_kwargs: Any) -> None:
                from maljan.core.config import Settings
                from maljan.core.container import ServiceContainer

                self.container = ServiceContainer(Settings(_env_file=None), mock=True)
                self.captures = staging.open_capture_dir(self.container.job_key())
                (self.captures / "rest_1.pcap").write_bytes(EMPTY_CAPTURE)
                made.append(self)

            def run(self, **_kwargs: Any) -> dict[str, Any]:
                raise ending[-1]

            async def aclose(self) -> None:
                released.append(self.container.job_key())
                staging.remove_job_staging(self.container.job_key())

        monkeypatch.setattr(cli, "MaljanApp", _App)
        for how_it_ends in (RuntimeError("the pipeline failed"), KeyboardInterrupt()):
            ending.append(how_it_ends)
            with pytest.raises((typer.Exit, KeyboardInterrupt)):
                cli.analyze(file_hash="a" * 64, mock=True)

        assert len(released) == 2, "both ways out released the run"
        for app in made:
            assert not app.captures.parent.exists()

    def test_a_run_that_never_started_releases_nothing(self) -> None:
        from maljan import cli

        assert cli._release(None) is None


class TestAProbeLeafIsPerCall:
    def test_two_calls_on_one_server_do_not_share_a_directory(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One operator's cleanup must not take away another's directory."""
        import inspect

        from apps.api.app.services import settings_probes

        source = inspect.getsource(settings_probes.handshake)
        assert 'probe_key = f"probe-{name}-{uuid.uuid4().hex[:8]}"' in source
        assert source.count("probe_key") >= 4, "the same key opens, detaches and is removed"

    def test_the_timeout_path_removes_it_too(self) -> None:
        """The branch that raises is the one on which a server really started."""
        import ast
        import inspect

        from apps.api.app.services import settings_probes

        tree = ast.parse(inspect.getsource(settings_probes.handshake).lstrip())
        guarded = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Try)
            for statement in node.finalbody
            if "remove_job_staging" in ast.dump(statement)
            for raised in ast.walk(node)
            if isinstance(raised, ast.Raise)
        ]

        assert guarded, "the timeout raises inside the block that removes"

    def test_the_agent_probe_carries_one_identity_for_the_whole_call(self) -> None:
        import inspect

        from apps.api.app.services import settings_probes

        source = inspect.getsource(settings_probes.probe_agent)
        assert 'job_key = f"probe-{name}-{uuid.uuid4().hex[:8]}"' in source
        assert "ServiceContainer(settings, mock=True, job_id=job_key)" in source


class TestTheCaptureDirectoryIsHeldToTheSameRuleAsStaging:
    def test_a_base_somebody_else_owns_is_refused_by_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "staging"))
        monkeypatch.setattr(staging.os, "getuid", lambda: -1)

        with pytest.raises(RuntimeError, match="owned by another user"):
            staging.open_capture_dir("one")

    def test_a_symlink_planted_at_the_capture_directory_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        base = tmp_path / "staging"
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
        captures = staging.job_capture_dir("one")
        captures.parent.mkdir(mode=0o700, parents=True)
        captures.symlink_to(elsewhere)

        with pytest.raises(RuntimeError, match="symlink"):
            staging.open_capture_dir("one")
        assert list(elsewhere.iterdir()) == []

    def test_one_rule_serves_both_sides(self) -> None:
        """The sidecar's own check is the same function, not a second copy."""
        import inspect

        server = TestTheSweepReachesAJobDirectory._server()

        assert "staging.private_dir" in inspect.getsource(server._private_dir)


class TestACaptureIsPrivateFromItsFirstByte:
    class _Response:
        def __init__(self, chunks: list[bytes], boom: bool = False) -> None:
            self._chunks = chunks
            self._boom = boom

        def iter_bytes(self, _size: int) -> Any:
            yield from self._chunks
            if self._boom:
                raise OSError("the connection went away")

    def test_it_is_created_0600_rather_than_chmodded_afterwards(self, tmp_path: Path) -> None:
        from maljan.providers.sandbox.limits import stream_to_file_capped

        out = tmp_path / "rest_1.pcap"
        modes: list[int] = []

        class _Watching(TestACaptureIsPrivateFromItsFirstByte._Response):
            def iter_bytes(self, size: int) -> Any:
                for chunk in super().iter_bytes(size):
                    modes.append(stat.S_IMODE(out.lstat().st_mode))
                    yield chunk

        stream_to_file_capped(_Watching([b"A" * 32, b"B" * 32]), out, what="The capture")

        assert modes and set(modes) == {0o600}, "private while it is being written"
        assert stat.S_IMODE(out.lstat().st_mode) == 0o600

    def test_a_stream_that_fails_leaves_no_partial(self, tmp_path: Path) -> None:
        from maljan.providers.sandbox.limits import stream_to_file_capped

        out = tmp_path / "rest_2.pcap"

        with pytest.raises(OSError, match="went away"):
            stream_to_file_capped(self._Response([b"A" * 32], boom=True), out, what="The capture")

        assert not out.exists()

    def test_a_symlink_at_the_destination_is_not_followed(self, tmp_path: Path) -> None:
        from maljan.providers.sandbox.limits import stream_to_file_capped

        target = tmp_path / "somebody-elses"
        target.write_bytes(b"NOT-THIS\x00")
        out = tmp_path / "rest_3.pcap"
        out.symlink_to(target)

        with pytest.raises(OSError):
            stream_to_file_capped(self._Response([b"A" * 32]), out, what="The capture")

        assert target.read_bytes() == b"NOT-THIS\x00"

    def test_a_capture_too_small_to_read_is_not_left_on_disk(self, tmp_path: Path) -> None:
        """Every provider answers ``None`` for a capture under the libpcap
        header's own length; the bytes go with the answer."""
        import inspect

        from maljan.loaders import cape2_client
        from maljan.providers.sandbox import rest, triage

        for source in (
            inspect.getsource(rest.RestSandboxProvider.fetch_pcap),
            inspect.getsource(triage.TriageSandboxProvider.fetch_pcap),
            inspect.getsource(cape2_client.CAPEv2Client.fetch_pcap),
        ):
            assert source.count("unlink(missing_ok=True)") >= 2, source[:80]


class TestTheLegacyCaptureDirectoryCanActuallyGo:
    def test_a_link_left_in_it_is_unlinked_and_the_directory_follows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = TestTheSweepReachesAJobDirectory._server()
        base = tmp_path / "staging"
        base.mkdir(parents=True)
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
        monkeypatch.setenv(staging.STAGING_TTL_ENV, "1")
        monkeypatch.setattr(server.tempfile, "gettempdir", lambda: str(tmp_path))
        legacy = tmp_path / staging.LEGACY_CAPTURE_DIR_NAME
        legacy.mkdir()
        elsewhere = tmp_path / "somebody-elses.pcap"
        elsewhere.write_bytes(EMPTY_CAPTURE)
        (legacy / "pointer.pcap").symlink_to(elsewhere)

        server._prune_staging(base)

        assert not legacy.exists(), "the directory goes once the link is out of it"
        assert elsewhere.exists(), "and the link was never followed"
