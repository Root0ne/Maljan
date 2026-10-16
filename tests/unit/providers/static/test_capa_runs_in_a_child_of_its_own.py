"""capa runs in a child process of its own: no worker secret, an answer file, the same answers.

The child used to be a ``multiprocessing`` spawn, which hands a child the
parent's whole environment: the database URL, the settings encryption key,
the token key, the object store and queue credentials. It is now started as
``python -I`` with the environment the stdio servers get (``child_env``) and
its run directory as home and temporary directory, writes its answer to a
file there, and is reaped with ``os.wait4``.

The children here are small interpreter runs the test writes, standing in for
capa: one reports the names it sees (never their values), one hangs, one dies,
one answers. The credential-shaped values are built at runtime
(``tests/credential_shapes.py``).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
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


@pytest.fixture(autouse=True)
def _scratch_in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    scratch = tmp_path / "staging"
    monkeypatch.setenv(staging.STAGING_DIR_ENV, str(scratch))
    return scratch


def _sample_and_rules(tmp_path: Path) -> tuple[Path, Path]:
    samples = tmp_path / "samples"
    samples.mkdir()
    sample = samples / "s.bin"
    sample.write_bytes(b"MZ")
    rules = tmp_path / "capa-rules"
    rules.mkdir()
    (rules / "r.yml").write_text("rule:\n  meta:\n    name: r\n", encoding="utf-8")
    return sample, rules


def _run(sample: Path, rules: Path, code: str, timeout: float | None = 30) -> dict[str, Any] | None:
    return capa_yara.run_capa_document(
        sample_path=str(sample),
        rules_dir=str(rules),
        signatures_dir="",
        backend_name="auto",
        timeout_seconds=timeout,
        child=[sys.executable, "-c", code],
    )


# Reports what it was started with: the names of its environment, never their
# values, and where its home, temporary directory and working directory are.
_REPORT = (
    "import json, os, sys\n"
    "seen = {'names': sorted(os.environ), 'home': os.environ.get('HOME'),"
    " 'tmp': os.environ.get('TMPDIR'), 'cwd': os.getcwd()}\n"
    "open(sys.argv[-1], 'w').write(json.dumps({'ok': seen}))\n"
)


class TestTheEnvironment:
    def test_no_secret_of_the_worker_reaches_the_child(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, _scratch_in_tmp: Path
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

        seen = _run(sample, rules, _REPORT)

        assert seen is not None
        assert not set(canaries) & set(seen["names"])
        assert set(seen["names"]) <= set(BASE_KEYS) | {"HOME", "TMPDIR"}
        # Its home, temporary and working directory: its own run directory,
        # inside this job's scratch directory and away from the sample.
        run = Path(seen["cwd"])
        assert seen["home"] == seen["tmp"] == str(run)
        assert run.parent == _scratch_in_tmp / "capa"
        assert run.name.startswith("run-")

    def test_the_child_is_started_isolated_by_its_entry_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        started: list[tuple[list[str], dict[str, str]]] = []
        real = capa_yara.subprocess.Popen

        def spy(command: list[str], **kwargs: Any) -> Any:
            started.append((list(command), dict(kwargs["env"])))
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

        ((command, env),) = started
        assert command[:3] == [sys.executable, "-I", str(capa_yara._CHILD_ENTRY)]
        assert command[3:7] == [str(sample), str(rules), "", "auto"]
        assert "DATABASE_URL" not in env
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
        self, tmp_path: Path, _scratch_in_tmp: Path
    ) -> None:
        sample, rules = _sample_and_rules(tmp_path)
        litter = (
            "import json, sys\n"
            "open('left-behind.txt', 'w').write('x')\n"
            "open(sys.argv[-1], 'w').write(json.dumps({'ok': {'rules': {}}}))\n"
        )

        assert _run(sample, rules, litter) == {"rules": {}}
        assert _run(sample, rules, "import os\nos._exit(1)\n") is None
        assert _run(sample, rules, "import time\ntime.sleep(30)\n", timeout=1) is None

        assert list((_scratch_in_tmp / "capa").iterdir()) == []
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

        assert capa_child.main([str(sample), str(rules), "", "auto", str(answer)]) == 0

        written = json.loads(answer.read_text(encoding="utf-8"))
        assert list(written) == ["error"] and written["error"]
        assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith("answer")) == [
            "answer.json"
        ]
