"""capa runs in a child process of its own: no worker secret, an answer file, the same answers.

The child used to be a ``multiprocessing`` spawn, which hands a child the
parent's whole environment: the database URL, the settings encryption key,
the token key, the object store and queue credentials. It is now started as
``python -I`` with the environment the stdio servers get (``child_env``) and
its run directory as home and temporary directory, writes its answer to a
file there, and is reaped with ``os.wait4``. The run directory is in the job's
own staging directory, so it goes with the job however the run ends; with no
job, it is a temporary directory of its own.

The children here are small interpreter runs the test writes, standing in for
capa: one reports the names it sees (never their values), one hangs, one dies,
one answers. The credential-shaped values are built at runtime
(``tests/credential_shapes.py``).
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.subprocess_env import BASE_KEYS
from maljan.providers.static import capa_yara
from maljan.tools import rules as tool
from maljan.tools import staging
from tests.credential_shapes import lowercase_body, password

# What the tool answers when the child gave no document, as it always has.
NO_RESULT = (
    "capa produced no result within its budget, or its worker exited without an answer "
    "(the server log says which)"
)

# The job the worker-side runs here belong to.
JOB = "a-capa-job"


@pytest.fixture(autouse=True)
def _scratch_in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The staging base, and the system's temporary directory, both under the test's own."""
    scratch = tmp_path / "staging"
    monkeypatch.setenv(staging.STAGING_DIR_ENV, str(scratch))
    monkeypatch.delenv(staging.STAGING_JOB_ENV, raising=False)
    loose = tmp_path / "tmp"
    loose.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(loose))
    return scratch


@pytest.fixture
def _job_capa() -> Iterator[Path]:
    """The job's capa directory, opened as the triage pack opens it; the teardown after."""
    opened = staging.open_job_directory(JOB, staging.CAPA_DIRECTORY)
    yield opened
    staging.remove_job_staging(JOB)


def _sample_and_rules(tmp_path: Path) -> tuple[Path, Path]:
    samples = tmp_path / "samples"
    samples.mkdir()
    sample = samples / "s.bin"
    sample.write_bytes(b"MZ")
    rules = tmp_path / "capa-rules"
    rules.mkdir()
    (rules / "r.yml").write_text("rule:\n  meta:\n    name: r\n", encoding="utf-8")
    return sample, rules


def _run(
    sample: Path,
    rules: Path,
    code: str,
    timeout: float | None = 30,
    scratch: Path | None = None,
) -> dict[str, Any] | None:
    return capa_yara.run_capa_document(
        sample_path=str(sample),
        rules_dir=str(rules),
        signatures_dir="",
        backend_name="auto",
        timeout_seconds=timeout,
        child=[sys.executable, "-c", code],
        scratch=scratch,
    )


# Reports what it was started with: the names of its environment, never their
# values, and where its home, temporary directory and working directory are,
# and who may enter the last.
_REPORT = (
    "import json, os, sys\n"
    "seen = {'names': sorted(os.environ), 'home': os.environ.get('HOME'),"
    " 'tmp': os.environ.get('TMPDIR'), 'cwd': os.getcwd(),"
    " 'mode': oct(os.stat('.').st_mode & 0o777)}\n"
    "open(sys.argv[-1], 'w').write(json.dumps({'ok': seen}))\n"
)


class TestTheEnvironment:
    def test_no_secret_of_the_worker_reaches_the_child(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _job_capa: Path
    ) -> None:
        canaries = {
            "DATABASE_URL": f"postgresql+asyncpg://maljan:{password()}@db:5432/maljan",
            "SETTINGS_ENCRYPTION_KEY": lowercase_body(44),
            "JWT_SECRET_KEY": lowercase_body(64),
            "MINIO_SECRET_KEY": password(24),
            "MINIO_ACCESS_KEY": password(16, variant=1),
            "REDIS_URL": f"redis://:{password(variant=2)}@redis:6379/0",
            "ANTHROPIC_API_KEY": lowercase_body(40),
            "XDG_CACHE_HOME": str(tmp_path / "worker-cache"),
        }
        for name, value in canaries.items():
            monkeypatch.setenv(name, value)
        sample, rules = _sample_and_rules(tmp_path)

        seen = _run(sample, rules, _REPORT, scratch=_job_capa)

        assert seen is not None
        assert not set(canaries) & set(seen["names"])
        assert set(seen["names"]) <= set(BASE_KEYS) | {"HOME", "TMPDIR"}
        # Its home, temporary and working directory: its own run directory,
        # inside the job's capa directory and away from the sample.
        run = Path(seen["cwd"])
        assert seen["home"] == seen["tmp"] == str(run)
        assert run.parent == _job_capa
        assert run.name.startswith("run-")

    def test_the_child_is_started_isolated_by_its_entry_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        started: list[tuple[list[str], dict[str, Any]]] = []
        real = capa_yara.subprocess.Popen

        def spy(command: list[str], **kwargs: Any) -> Any:
            started.append((list(command), dict(kwargs)))
            return real(command, **kwargs)

        monkeypatch.setattr(capa_yara.subprocess, "Popen", spy)
        monkeypatch.setenv("DATABASE_URL", f"postgresql://maljan:{password()}@db/maljan")
        sample, rules = _sample_and_rules(tmp_path)

        capa_yara.run_capa_document(
            sample_path=str(sample),
            rules_dir=str(rules),
            signatures_dir="",
            backend_name="auto",
            timeout_seconds=60,
        )

        ((command, kwargs),) = started
        assert command[:3] == [sys.executable, "-I", str(capa_yara._CHILD_ENTRY)]
        assert command[3:8] == [str(sample), str(rules), "", "auto", str(os.getpid())]
        assert "DATABASE_URL" not in kwargs["env"]
        # In the caller's process group, so a kill of the caller's group reaches it.
        assert not kwargs.get("start_new_session") and not kwargs.get("process_group")
        # The entry imports nothing of the platform: the standard library and capa only.
        source = capa_yara._CHILD_ENTRY.read_text(encoding="utf-8")
        assert "import maljan" not in source and "from maljan" not in source


def _entry(tmp_path: Path, code: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """A child entry file of the test's own, run as the real one is: ``python -I <file>``."""
    entry = tmp_path / "entry.py"
    entry.write_text(code, encoding="utf-8")
    monkeypatch.setattr(capa_yara, "_CHILD_ENTRY", entry)


class TestTheSameAnswers:
    def test_a_child_that_hangs_is_killed_at_the_budget(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        pid_file = tmp_path / "child.pid"
        _entry(
            tmp_path,
            f"import os, time\nopen({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
            "time.sleep(30)\n",
            monkeypatch,
        )
        sample, rules = _sample_and_rules(tmp_path)

        started = time.monotonic()
        with caplog.at_level(logging.WARNING):
            answer = tool.capa(str(sample), timeout_s=1, rules_dir=str(rules))

        assert answer == {"error": NO_RESULT, "tool": "capa"}
        assert time.monotonic() - started < 15
        assert any("exceeded its 1s budget" in r.getMessage() for r in caplog.records)
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)

    def test_a_child_that_dies_without_writing_gives_the_same_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        _entry(tmp_path, "import os\nos._exit(3)\n", monkeypatch)
        sample, rules = _sample_and_rules(tmp_path)

        with caplog.at_level(logging.WARNING):
            answer = tool.capa(str(sample), timeout_s=30, rules_dir=str(rules))

        assert answer == {"error": NO_RESULT, "tool": "capa"}
        assert any(
            "exited without an answer (exit code 3)" in r.getMessage() for r in caplog.records
        )

    def test_capa_s_own_error_is_said_as_before(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        sample, rules = _sample_and_rules(tmp_path)
        failing = (
            "import json, sys\n"
            "open(sys.argv[-1], 'w').write(json.dumps({'error': 'ValueError: no rules'}))\n"
        )

        with caplog.at_level(logging.WARNING):
            assert _run(sample, rules, failing) is None

        assert any("capa failed on" in r.getMessage() for r in caplog.records)
        assert any("(ValueError: no rules)" in r.getMessage() for r in caplog.records)


class TestTheScratch:
    def test_the_run_directory_goes_and_nothing_lands_beside_the_sample(
        self, tmp_path: Path, _job_capa: Path
    ) -> None:
        sample, rules = _sample_and_rules(tmp_path)
        litter = (
            "import json, sys\n"
            "open('left-behind.txt', 'w').write('x')\n"
            "open(sys.argv[-1], 'w').write(json.dumps({'ok': {'rules': {}}}))\n"
        )

        for scratch in (_job_capa, None):
            assert _run(sample, rules, litter, scratch=scratch) == {"rules": {}}
            assert _run(sample, rules, "import os\nos._exit(1)\n", scratch=scratch) is None
            hang = "import time\ntime.sleep(30)\n"
            assert _run(sample, rules, hang, timeout=1, scratch=scratch) is None

        assert list(_job_capa.iterdir()) == []
        assert list(Path(tempfile.gettempdir()).iterdir()) == []
        assert [p.name for p in sample.parent.iterdir()] == ["s.bin"]

    def test_an_answer_written_by_half_is_no_answer(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        sample, rules = _sample_and_rules(tmp_path)
        partial = "import sys\nopen(sys.argv[-1], 'w').write('{\"ok\": {\"rules\"')\n"

        with caplog.at_level(logging.WARNING):
            assert _run(sample, rules, partial) is None

        assert any(
            "exited without an answer (exit code 0)" in r.getMessage() for r in caplog.records
        )

    def test_the_child_entry_writes_an_answer_whole_even_when_capa_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Run in this process: a file capa cannot read gives capa's error, written whole."""
        from maljan.providers.static import capa_child

        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        sample, rules = _sample_and_rules(tmp_path)
        answer = tmp_path / "answer.json"

        capa_child.answer_to_file(str(sample), str(rules), "", "auto", str(answer))

        written = json.loads(answer.read_text(encoding="utf-8"))
        assert list(written) == ["error"] and written["error"]
        assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith("answer")) == [
            "answer.json"
        ]


# The child entry, loaded by its path as the real child runs it: it imports
# only the standard library, so no package of the platform comes with it.
_LOAD_ENTRY = (
    "import importlib.util, os, sys, time\n"
    "spec = importlib.util.spec_from_file_location('capa_child', {entry!r})\n"
    "capa_child = importlib.util.module_from_spec(spec)\n"
    "spec.loader.exec_module(capa_child)\n"
)

# A stand-in for the capa child that does what the real one does first, dies
# with its parent, then says its pid and sleeps far past any wait here.
_DYING_SLEEPER = _LOAD_ENTRY + (
    "capa_child.die_with_parent(int(sys.argv[-2]))\n"
    "open({pid_file!r}, 'w').write(str(os.getpid()))\n"
    "time.sleep(120)\n"
)


def _entry_code(body: str) -> str:
    return _LOAD_ENTRY.format(entry=str(capa_yara._CHILD_ENTRY)) + body


# The parent: one capa run with no budget, in its main thread ("main"), or on a
# daemon thread with the main thread exiting once the child is there ("exit");
# in the job's capa directory, opened as the triage pack opens it, when a job
# is named.
_PARENT = (
    "import os, sys, threading, time\n"
    "from pathlib import Path\n"
    "from maljan.providers.static import capa_yara\n"
    "from maljan.tools import staging\n"
    "child_code, pid_file, mode, job = sys.argv[1:5]\n"
    "sample = Path(pid_file).with_name('s.bin')\n"
    "sample.write_bytes(b'MZ')\n"
    "scratch = staging.open_job_directory(job, staging.CAPA_DIRECTORY) if job else None\n"
    "def call():\n"
    "    capa_yara.run_capa_document(sample_path=str(sample), rules_dir=str(sample.parent),\n"
    "        signatures_dir='', backend_name='auto', timeout_seconds=None,\n"
    "        child=[sys.executable, '-c', child_code], scratch=scratch)\n"
    "if mode == 'main':\n"
    "    call()\n"
    "else:\n"
    "    threading.Thread(target=call, daemon=True).start()\n"
    "    deadline = time.monotonic() + 30\n"
    "    while time.monotonic() < deadline:\n"
    "        if os.path.exists(pid_file) and open(pid_file).read():\n"
    "            break\n"
    "        time.sleep(0.05)\n"
    "    sys.exit(0)\n"
)


def _running(pid: int) -> bool:
    """Whether ``pid`` is a live process: present, and not a zombie waiting to be reaped."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except (FileNotFoundError, ProcessLookupError):
        return False
    return stat.rsplit(")", 1)[1].split()[0] != "Z"


def _gone_within(pid: int, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not _running(pid):
            return True
        time.sleep(0.05)
    return False


# A stand-in that does not ask to die with its parent: what reaches it is only
# what reaches the parent's process group.
_PLAIN_SLEEPER = (
    "import os, time\nopen({pid_file!r}, 'w').write(str(os.getpid()))\ntime.sleep(120)\n"
)


class _Parent:
    """A parent process running one capa run whose child is a sleeper, dying with it or not."""

    def __init__(
        self,
        tmp_path: Path,
        mode: str,
        *,
        own_session: bool = False,
        dies_with_it: bool = True,
        job: str = "",
    ) -> None:
        self.pid_file = tmp_path / "child.pid"
        env = {
            **os.environ,
            "PYTHONPATH": os.pathsep.join(p for p in sys.path if p),
            staging.STAGING_DIR_ENV: str(tmp_path / "staging"),
            "TMPDIR": str(tmp_path / "tmp"),
        }
        env.pop(staging.STAGING_JOB_ENV, None)
        sleeper = _DYING_SLEEPER if dies_with_it else _PLAIN_SLEEPER
        child_code = sleeper.format(entry=str(capa_yara._CHILD_ENTRY), pid_file=str(self.pid_file))
        self.process = subprocess.Popen(
            [sys.executable, "-c", _PARENT, child_code, str(self.pid_file), mode, job],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            start_new_session=own_session,
        )
        self.child = 0

    def child_pid(self) -> int:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            text = self.pid_file.read_text(encoding="utf-8") if self.pid_file.exists() else ""
            if text:
                self.child = int(text)
                return self.child
            time.sleep(0.05)
        pytest.fail("the stand-in child never started")

    def clean_up(self) -> None:
        """Leave nothing behind whatever the test found."""
        if self.child and _running(self.child):
            os.kill(self.child, signal.SIGKILL)
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=30)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc; prctl is Linux's")
class TestTheChildDiesWithItsParent:
    def test_a_parent_killed_outright_takes_its_child(self, tmp_path: Path) -> None:
        parent = _Parent(tmp_path, "main")
        try:
            child = parent.child_pid()
            os.kill(parent.process.pid, signal.SIGKILL)
            parent.process.wait(timeout=30)

            assert _gone_within(child, 10)
        finally:
            parent.clean_up()

    def test_a_parent_that_exits_takes_its_child(self, tmp_path: Path) -> None:
        parent = _Parent(tmp_path, "exit")
        try:
            child = parent.child_pid()
            assert parent.process.wait(timeout=30) == 0

            assert _gone_within(child, 10)
        finally:
            parent.clean_up()

    def test_a_group_kill_of_the_parent_takes_its_child(self, tmp_path: Path) -> None:
        """As mcp stops a server: SIGTERM to its group, SIGKILL two seconds later.

        The stand-in does not ask to die with its parent, so this holds by the
        process group alone: the child is in its caller's group.
        """
        parent = _Parent(tmp_path, "main", own_session=True, dies_with_it=False)
        try:
            child = parent.child_pid()
            os.killpg(parent.process.pid, signal.SIGTERM)
            try:
                parent.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(parent.process.pid, signal.SIGKILL)
                parent.process.wait(timeout=30)

            assert _gone_within(child, 10)
        finally:
            parent.clean_up()

    def test_a_child_whose_parent_has_already_gone_leaves_at_once(self) -> None:
        from maljan.providers.static.capa_child import PARENT_GONE_EXIT

        code = _entry_code("capa_child.die_with_parent(1)\nraise SystemExit(0)\n")

        done = subprocess.run(
            [sys.executable, "-I", "-c", code], capture_output=True, timeout=60, check=False
        )

        assert done.returncode == PARENT_GONE_EXIT

    def test_without_prctl_it_says_so_and_watches_its_parent(self) -> None:
        code = _entry_code(
            "sys.platform = 'no-prctl'\nprint(capa_child.die_with_parent(os.getppid()))\n"
        )

        done = subprocess.run(
            [sys.executable, "-I", "-c", code],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        assert done.stdout.strip() == "False"
        assert "prctl(PR_SET_PDEATHSIG) is not available here" in done.stderr


class TestTheRunDirectoryGoesWithTheJob:
    """In the job's own directory, which its teardown and the sweep reach; else a temporary one."""

    def test_a_server_started_for_a_job_runs_in_its_own_job_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _scratch_in_tmp: Path
    ) -> None:
        leaf = staging.job_directory_name(JOB)
        monkeypatch.setenv(staging.STAGING_JOB_ENV, leaf)
        sample, rules = _sample_and_rules(tmp_path)

        seen = _run(sample, rules, _REPORT)

        assert seen is not None
        run = Path(seen["cwd"])
        assert run.parent == _scratch_in_tmp / leaf / staging.CAPA_DIRECTORY
        assert not run.exists()

    def test_with_no_job_directory_a_run_has_a_temporary_directory_of_its_own(
        self, tmp_path: Path, _scratch_in_tmp: Path
    ) -> None:
        sample, rules = _sample_and_rules(tmp_path)

        seen = _run(sample, rules, _REPORT)

        assert seen is not None
        run = Path(seen["cwd"])
        assert run.parent == Path(tempfile.gettempdir())
        assert run.name.startswith("maljan-capa-")
        assert seen["mode"] == "0o700"
        assert not run.exists()
        # Nothing under the staging base, where no job's teardown would look.
        assert not _scratch_in_tmp.exists()

    def test_the_provider_runs_in_its_job_s_directory_which_the_teardown_removes(
        self, tmp_path: Path, _scratch_in_tmp: Path
    ) -> None:
        from maljan.core.config import Settings

        provider = capa_yara.CapaYaraStaticProvider.from_settings(Settings(_env_file=None))
        provider.job_key = JOB
        sample, rules = _sample_and_rules(tmp_path)
        job_dir = staging.job_staging_dir(_scratch_in_tmp, JOB)
        try:
            seen = provider._run_capa_bounded(
                str(sample), rules, child=[sys.executable, "-c", _REPORT]
            )

            assert seen is not None
            assert Path(seen["cwd"]).parent == job_dir / staging.CAPA_DIRECTORY
            assert staging.job_directories(JOB) == [job_dir]
        finally:
            staging.remove_job_staging(JOB)
        assert not job_dir.exists()

    def test_the_pack_s_step_hands_capa_its_job_s_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Opened under the capa server's base, recorded for the teardown; the args as before."""
        from maljan.agents.evidence_recorder import EvidenceRecorder
        from maljan.core.pack_steps import default_steps
        from maljan.pipeline.triage_pack import PIPELINE, CapaSettings, PackInputs, run_pack
        from maljan.schemas.evidence import EvidenceCounter

        handed: list[dict[str, Any]] = []

        def capa(path: str, **kwargs: Any) -> dict[str, Any]:
            handed.append(kwargs)
            return {"capabilities": [], "meta": {}}

        monkeypatch.setattr(tool, "capa", capa)
        base = tmp_path / "server-base"
        sample, rules = _sample_and_rules(tmp_path)
        settings = CapaSettings(
            rules_dir=str(rules),
            signatures_dir="",
            timeout_s=5,
            environ={staging.STAGING_DIR_ENV: str(base)},
            job_id=JOB,
        )
        inputs = PackInputs(
            sample_path=str(sample),
            sha256="a" * 64,
            file_type="pe",
            strings_head=10,
            capa=settings,
            steps=tuple(s for s in default_steps() if s.id == "capa"),
        )
        job_dir = staging.job_staging_dir(base, JOB)
        try:
            result = run_pack(
                EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack"), inputs
            )

            assert [kwargs["scratch"] for kwargs in handed] == [job_dir / staging.CAPA_DIRECTORY]
            assert staging.job_directories(JOB) == [job_dir]
            (entry,) = [e for e in result.entries if e.tool == "capa"]
            assert sorted(entry.args) == [
                "backend",
                "path",
                "rules_dir",
                "signatures_dir",
                "timeout_s",
            ]
        finally:
            staging.remove_job_staging(JOB)
        assert not job_dir.exists()

    def test_the_container_tells_the_provider_its_job(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        cfg = Settings(_env_file=None)
        cfg.static.provider = "capa_yara"
        container = ServiceContainer(config=cfg, mock=True, job_id=JOB)

        provider = container.get_static_provider()

        assert isinstance(provider, capa_yara.CapaYaraStaticProvider)
        assert provider.job_key == container.job_key() == JOB

    @pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
    def test_after_a_killed_parent_nothing_is_left_outside_the_job_directory(
        self, tmp_path: Path
    ) -> None:
        parent = _Parent(tmp_path, "main", job=JOB)
        try:
            child = parent.child_pid()
            os.kill(parent.process.pid, signal.SIGKILL)
            parent.process.wait(timeout=30)

            assert _gone_within(child, 10)
        finally:
            parent.clean_up()

        base = tmp_path / "staging"
        job_dir = staging.job_staging_dir(base, JOB)
        # The dead parent's run directory is still there, inside the job's
        # directory: one the job's teardown removes, and one the server's
        # sweep of job directories reaches by its name.
        assert [p.name for p in base.iterdir()] == [job_dir.name]
        assert staging.is_job_directory_name(job_dir.name)
        (run,) = (job_dir / staging.CAPA_DIRECTORY).iterdir()
        assert run.name.startswith("run-")
        assert all(job_dir in p.parents for p in base.rglob("*") if p != job_dir)
        # And nothing went to the temporary directory.
        assert list((tmp_path / "tmp").iterdir()) == []

    def test_a_run_with_no_job_first_sweeps_what_killed_runs_left_past_the_ttl(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(staging.STAGING_TTL_ENV, "1")
        loose = Path(tempfile.gettempdir())
        stale = loose / "maljan-capa-left"
        (stale / ".cache").mkdir(parents=True)
        (stale / ".cache" / "capa.cache").write_bytes(b"x")
        fresh = loose / "maljan-capa-running"
        fresh.mkdir()
        other = loose / "someone-else"
        other.mkdir()
        hours_ago = time.time() - 2 * 3600
        for path in (other, stale / ".cache" / "capa.cache", stale / ".cache", stale):
            os.utime(path, (hours_ago, hours_ago))
        sample, rules = _sample_and_rules(tmp_path)

        assert _run(sample, rules, _REPORT) is not None

        # The stale one went; one touched within the TTL, and anything not a
        # capa run's, stays; the run's own directory went when it ended.
        assert sorted(p.name for p in loose.iterdir()) == ["maljan-capa-running", "someone-else"]

    def test_a_ttl_of_zero_sweeps_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(staging.STAGING_TTL_ENV, "0")
        stale = Path(tempfile.gettempdir()) / "maljan-capa-left"
        stale.mkdir()
        os.utime(stale, (0, 0))
        sample, rules = _sample_and_rules(tmp_path)

        assert _run(sample, rules, _REPORT) is not None

        assert stale.is_dir()

    def test_a_run_in_a_job_does_not_sweep_the_temporary_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _job_capa: Path
    ) -> None:
        monkeypatch.setenv(staging.STAGING_TTL_ENV, "1")
        stale = Path(tempfile.gettempdir()) / "maljan-capa-left"
        stale.mkdir()
        os.utime(stale, (0, 0))
        sample, rules = _sample_and_rules(tmp_path)

        assert _run(sample, rules, _REPORT, scratch=_job_capa) is not None

        assert stale.is_dir()
