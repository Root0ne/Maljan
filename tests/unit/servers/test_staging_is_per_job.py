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
    """One live analysis sidecar, attached for one job id."""

    def __init__(self, job_id: str) -> None:
        self.job_id = job_id
        self.handle: Any = None

    async def open(self) -> None:
        from maljan.core.settings_overrides import build_settings
        from maljan.providers.servers import ServerHandle

        self.handle = ServerHandle("analysis", build_settings({}).mcp.servers["analysis"])
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
