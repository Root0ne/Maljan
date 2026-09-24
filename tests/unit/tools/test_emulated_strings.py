"""``maljan.tools.emulated_strings`` reads FLOSS's result document row by row.

FLOSS itself is not run here: the runner is replaced by one that answers with
a result document in FLOSS's own shape, so what these tests pin is the reading
of that document — every string with the function that produced it, paging
that counts rows, one emulation however many pages are read, and an error in
the tool's words for every way the child can fail.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from maljan.tools import emulated_strings as tool

IMAGEBASE = 0x180000000


def _document() -> dict[str, Any]:
    """A result document in FLOSS's shape, with made-up strings."""
    return {
        "metadata": {
            "version": "3.1.1",
            "imagebase": IMAGEBASE,
            "language": "unknown",
            "runtime": {"total": 12.5},
        },
        "analysis": {"functions": {"discovered": 40, "analyzed_decoded_strings": 5}},
        "strings": {
            "decoded_strings": [
                {
                    "address": 0x7FFE0010,
                    "address_type": "STACK",
                    "string": "example-mutex",
                    "encoding": "ASCII",
                    "decoded_at": IMAGEBASE + 0x5C02,
                    "decoding_routine": IMAGEBASE + 0xAE78,
                },
                {
                    "address": IMAGEBASE + 0xD000,
                    "address_type": "GLOBAL",
                    "string": "https://c2.example.org/path/",
                    "encoding": "UTF-16LE",
                    "decoded_at": IMAGEBASE + 0x6A1F,
                    "decoding_routine": IMAGEBASE + 0xAE78,
                },
            ],
            "stack_strings": [
                {
                    "function": IMAGEBASE + 0x1000,
                    "string": "stackbuilt",
                    "encoding": "ASCII",
                    "program_counter": IMAGEBASE + 0x1044,
                    "stack_pointer": 0,
                    "original_stack_pointer": 0,
                    "offset": 8,
                    "frame_offset": 32,
                }
            ],
            "tight_strings": [],
            "static_strings": [],
        },
    }


class _Runner:
    """Answers every call with one completed process and counts the calls."""

    def __init__(self, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
        self.calls: list[list[str]] = []
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr

    def __call__(self, argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(list(argv), self.returncode, self.stdout, self.stderr)


@pytest.fixture(autouse=True)
def _nothing_remembered() -> None:
    tool.forget_documents()


def _pe(tmp_path: Path, name: str = "s.dll") -> str:
    target = tmp_path / name
    target.write_bytes(b"MZ" + b"\x00" * 62)
    return str(target)


class TestTheDocumentIsRead:
    def test_a_decoded_string_carries_the_function_that_decoded_it(self, tmp_path: Path) -> None:
        runner = _Runner(json.dumps(_document()))

        rows = tool.floss(_pe(tmp_path), runner=runner)["strings"]

        assert rows[0] == {
            "kind": "decoded",
            "string": "example-mutex",
            "encoding": "ASCII",
            "function": hex(IMAGEBASE + 0xAE78),
            "function_rva": "0xae78",
            "called_at": hex(IMAGEBASE + 0x5C02),
            "called_at_rva": "0x5c02",
            "address": hex(0x7FFE0010),
            "address_type": "STACK",
        }

    def test_a_stack_string_carries_its_function_and_frame_offset(self, tmp_path: Path) -> None:
        runner = _Runner(json.dumps(_document()))

        rows = tool.floss(_pe(tmp_path), runner=runner)["strings"]
        stack = [row for row in rows if row["kind"] == "stack"]

        assert stack == [
            {
                "kind": "stack",
                "string": "stackbuilt",
                "encoding": "ASCII",
                "function": hex(IMAGEBASE + 0x1000),
                "function_rva": "0x1000",
                "program_counter": hex(IMAGEBASE + 0x1044),
                "frame_offset": 32,
            }
        ]

    def test_counts_and_meta_say_what_floss_found(self, tmp_path: Path) -> None:
        answer = tool.floss(_pe(tmp_path), runner=_Runner(json.dumps(_document())))

        assert answer["counts"] == {"decoded": 2, "stack": 1, "tight": 0}
        assert answer["total"] == 3
        assert answer["meta"] == {
            "floss_version": "3.1.1",
            "imagebase": hex(IMAGEBASE),
            "language": "unknown",
            "functions_discovered": 40,
            "functions_emulated_for_decoding": 5,
            "runtime_s": 12.5,
        }

    def test_floss_is_asked_for_the_emulated_kinds_only_and_as_json(self, tmp_path: Path) -> None:
        runner = _Runner(json.dumps(_document()))
        path = _pe(tmp_path)

        tool.floss(path, min_len=5, runner=runner)

        argv = runner.calls[0]
        assert argv[0] == "floss"
        assert "--json" in argv
        assert argv[argv.index("--minimum-length") + 1] == "5"
        only = argv[argv.index("--only") + 1 : argv.index("--")]
        assert only == ["decoded", "stack", "tight"]
        assert argv[-1] == path

    def test_an_empty_answer_is_no_strings_rather_than_an_error(self, tmp_path: Path) -> None:
        answer = tool.floss(_pe(tmp_path), runner=_Runner(""))

        assert answer["strings"] == []
        assert answer["counts"] == {"decoded": 0, "stack": 0, "tight": 0}


class TestPaging:
    def test_pages_count_rows_and_say_where_the_next_one_starts(self, tmp_path: Path) -> None:
        runner = _Runner(json.dumps(_document()))
        path = _pe(tmp_path)

        first = tool.floss(path, limit=2, runner=runner)
        second = tool.floss(path, limit=2, offset=first["next_offset"], runner=runner)

        assert [row["string"] for row in first["strings"]] == [
            "example-mutex",
            "https://c2.example.org/path/",
        ]
        assert first["next_offset"] == 2
        assert first["truncated"] is True
        assert [row["string"] for row in second["strings"]] == ["stackbuilt"]
        assert second["next_offset"] is None

    def test_reading_every_page_costs_one_emulation(self, tmp_path: Path) -> None:
        runner = _Runner(json.dumps(_document()))
        path = _pe(tmp_path)

        for offset in range(3):
            tool.floss(path, limit=1, offset=offset, runner=runner)

        assert len(runner.calls) == 1

    def test_pattern_and_kinds_narrow_the_rows(self, tmp_path: Path) -> None:
        runner = _Runner(json.dumps(_document()))
        path = _pe(tmp_path)

        by_pattern = tool.floss(path, pattern="MUTEX", runner=runner)
        by_kind = tool.floss(path, kinds=["stack"], runner=runner)

        assert [row["string"] for row in by_pattern["strings"]] == ["example-mutex"]
        assert by_pattern["total_matched"] == 1
        assert by_pattern["total"] == 3
        assert [row["string"] for row in by_kind["strings"]] == ["stackbuilt"]


class TestFailuresAreAnswers:
    def test_a_file_that_is_not_a_pe_is_refused_before_floss_runs(self, tmp_path: Path) -> None:
        target = tmp_path / "script.txt"
        target.write_bytes(b"#!/bin/sh\n")
        runner = _Runner(json.dumps(_document()))

        answer = tool.floss(str(target), runner=runner)

        assert "not a PE" in answer["error"]
        assert runner.calls == []

    def test_an_overrun_is_a_timeout_the_error_codes_recognise(self, tmp_path: Path) -> None:
        from maljan.tools.errors import TIMEOUT, error_parts

        def runner(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
            raise subprocess.TimeoutExpired(list(argv), timeout)

        answer = tool.floss(_pe(tmp_path), timeout_s=7, runner=runner)

        parts = error_parts(answer)
        assert parts is not None
        assert parts[0] == TIMEOUT
        assert "7 s" in answer["error"]

    def test_a_failed_child_is_answered_with_its_last_stderr_line(self, tmp_path: Path) -> None:
        stderr = "loading\nfailed to analyze sample: bad header\n"
        runner = _Runner("", returncode=255, stderr=stderr)

        answer = tool.floss(_pe(tmp_path), runner=runner)

        assert answer["error"].endswith("failed to analyze sample: bad header")
        assert "255" in answer["error"]

    def test_output_that_is_not_the_document_is_an_error(self, tmp_path: Path) -> None:
        answer = tool.floss(_pe(tmp_path), runner=_Runner("not json"))

        assert "JSON document" in answer["error"]

    def test_an_unknown_kind_is_named(self, tmp_path: Path) -> None:
        answer = tool.floss(_pe(tmp_path), kinds=["static"], runner=_Runner("{}"))

        assert "static" in answer["error"]

    def test_a_missing_file_is_named(self, tmp_path: Path) -> None:
        answer = tool.floss(str(tmp_path / "absent.dll"), runner=_Runner("{}"))

        assert answer["error"].startswith("no such file")

    def test_without_the_executable_the_answer_says_how_to_install_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.tools.errors import MISSING_DEPENDENCY, error_parts

        monkeypatch.setenv("MALJAN_FLOSS_PATH", str(tmp_path / "absent"))

        answer = tool.floss(_pe(tmp_path))

        parts = error_parts(answer)
        assert parts is not None
        assert parts[0] == MISSING_DEPENDENCY
        assert parts[2] == tool.FLOSS_REMEDIATION
        assert str(tmp_path) not in json.dumps(answer), "the reason names a host path"

    def test_a_saved_workspace_beside_the_sample_is_refused(self, tmp_path: Path) -> None:
        path = _pe(tmp_path)
        Path(f"{path}.viv").write_bytes(b"not a workspace")
        runner = _Runner(json.dumps(_document()))

        answer = tool.floss(path, runner=runner)

        assert "saved vivisect workspace" in answer["error"]
        assert runner.calls == []

    @pytest.mark.parametrize(
        "returncode, stderr",
        [(1, "Traceback ...\nMemoryError\n"), (-6, ""), (-9, ""), (-11, "")],
    )
    def test_the_memory_limit_is_reported_as_the_budget(
        self, tmp_path: Path, returncode: int, stderr: str
    ) -> None:
        from maljan.tools.errors import TIMEOUT, error_parts

        answer = tool.floss(_pe(tmp_path), runner=_Runner("", returncode=returncode, stderr=stderr))

        parts = error_parts(answer)
        assert parts is not None
        assert parts[0] == TIMEOUT
        assert "MiB of address space" in answer["error"]


class TestTheExecutable:
    def _executable(self, tmp_path: Path, body: bytes) -> Path:
        target = tmp_path / "floss"
        target.write_bytes(body)
        target.chmod(0o755)
        return target

    def test_only_the_pinned_build_is_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = self._executable(tmp_path, b"#!/bin/sh\necho not floss\n")
        monkeypatch.setenv("MALJAN_FLOSS_PATH", str(target))

        found, reason = tool.find_floss()

        assert found is None
        assert "not the pinned FLOSS 3.1.1 build" in reason
        assert str(tmp_path) not in reason

    def test_the_configured_executable_with_the_pinned_digest_is_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import hashlib

        body = b"#!/bin/sh\n"
        target = self._executable(tmp_path, body)
        monkeypatch.setenv("MALJAN_FLOSS_PATH", str(target))
        monkeypatch.setattr(tool, "FLOSS_BINARY_SHA256", hashlib.sha256(body).hexdigest())

        assert tool.find_floss() == (target, "")
        assert tool.floss_unavailable() is None

    def test_the_user_tools_directory_is_looked_in(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import hashlib

        monkeypatch.delenv("MALJAN_FLOSS_PATH", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))
        body = b"#!/bin/sh\n"
        installed = tool.default_install_path()
        installed.parent.mkdir(parents=True)
        installed.write_bytes(body)
        installed.chmod(0o755)
        monkeypatch.setattr(tool, "FLOSS_BINARY_SHA256", hashlib.sha256(body).hexdigest())

        assert tool.find_floss() == (installed, "")
        assert (
            installed
            == tmp_path / ".local" / "share" / "maljan" / "tools" / "floss-3.1.1" / "floss"
        )

    def test_an_environment_handed_in_is_read_instead_of_this_process_s(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The triage pack looks with the analysis server's environment."""
        import hashlib

        body = b"#!/bin/sh\n"
        target = self._executable(tmp_path, body)
        monkeypatch.setattr(tool, "FLOSS_BINARY_SHA256", hashlib.sha256(body).hexdigest())
        monkeypatch.setenv("MALJAN_FLOSS_PATH", str(tmp_path / "absent"))

        assert tool.find_floss({"MALJAN_FLOSS_PATH": str(target)}) == (target, "")
        assert tool.floss_unavailable({"MALJAN_FLOSS_PATH": str(target)}) is None
        assert tool.floss_unavailable() is not None

    def test_the_search_path_handed_in_is_the_one_searched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import hashlib

        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        body = b"#!/bin/sh\n"
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        target = bin_dir / "floss"
        target.write_bytes(body)
        target.chmod(0o755)
        monkeypatch.setattr(tool, "FLOSS_BINARY_SHA256", hashlib.sha256(body).hexdigest())

        assert tool.find_floss({"PATH": str(bin_dir)}) == (target, "")
        assert tool.find_floss({"PATH": str(tmp_path / "empty")})[0] is None


class TestTheChild:
    @pytest.fixture(autouse=True)
    def _staging(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))
        monkeypatch.delenv("MALJAN_STAGING_JOB", raising=False)

    def test_the_child_gets_the_limit_and_a_home_inside_staging_and_nothing_else(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sys

        monkeypatch.setenv("A_SERVER_SECRET", "kept-out")
        script = (
            "import json, os, resource; print(json.dumps({"
            "'limit': resource.getrlimit(resource.RLIMIT_AS)[0], 'home': os.environ['HOME'], "
            "'tmp': os.environ['TMPDIR'], 'cwd': os.getcwd(), "
            "'secret': os.environ.get('A_SERVER_SECRET')}))"
        )

        finished = tool._run([sys.executable, "-c", script], 30)

        seen = json.loads(finished.stdout)
        scratch = tmp_path / "staging" / "floss"
        assert seen["limit"] == tool.FLOSS_ADDRESS_SPACE_BYTES
        assert seen["home"] == seen["tmp"] == seen["cwd"]
        assert Path(seen["home"]).parent == scratch
        assert Path(seen["home"]).name.startswith("run-")
        assert seen["secret"] is None
        # The run's own directory goes with the run.
        assert list(scratch.iterdir()) == []

    def test_a_scratch_directory_handed_in_holds_the_run(self, tmp_path: Path) -> None:
        """The triage pack's run goes in the job directory it opened."""
        import sys

        opened = tmp_path / "job-dir" / "floss"
        finished = tool._run(
            [sys.executable, "-c", "import os; print(os.getcwd())"], 30, scratch=opened
        )

        assert Path(finished.stdout.strip()).parent == opened
        assert list(opened.iterdir()) == []
        assert not (tmp_path / "staging" / "floss").exists()

    def test_an_overrun_kills_the_whole_group(self, tmp_path: Path) -> None:
        import os
        import sys
        import time

        marker = tmp_path / "grandchild.pid"
        script = (
            "import subprocess, sys, time; "
            f"p = subprocess.Popen(['sleep', '60']); open({str(marker)!r}, 'w').write(str(p.pid)); "
            "time.sleep(60)"
        )

        with pytest.raises(subprocess.TimeoutExpired):
            tool._run([sys.executable, "-c", script], 2)

        # What the killed run unpacked goes with it, not with the job.
        assert list((tmp_path / "staging" / "floss").iterdir()) == []
        grandchild = int(marker.read_text())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(grandchild, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            pytest.fail("the grandchild outlived the overrun")


class TestOneEmulationPerSample:
    def test_a_second_concurrent_caller_waits_for_the_first_result(self, tmp_path: Path) -> None:
        import threading
        import time

        calls: list[int] = []
        gate = threading.Event()

        def slow(argv: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
            calls.append(1)
            gate.wait(5)
            time.sleep(0.05)
            return subprocess.CompletedProcess(list(argv), 0, json.dumps(_document()), "")

        path = _pe(tmp_path)
        answers: list[dict[str, Any]] = []
        threads = [
            threading.Thread(target=lambda: answers.append(tool.floss(path, runner=slow)))
            for _ in range(2)
        ]
        for thread in threads:
            thread.start()
        time.sleep(0.2)
        gate.set()
        for thread in threads:
            thread.join(10)

        assert len(calls) == 1
        assert [answer["total"] for answer in answers] == [3, 3]


class TestWhatRunsIsWhatWasVerified:
    @pytest.fixture(autouse=True)
    def _staging(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MALJAN_STAGING_DIR", str(tmp_path / "staging"))
        monkeypatch.delenv("MALJAN_STAGING_JOB", raising=False)

    def _script(self, tmp_path: Path, text: str) -> tuple[Path, str]:
        import hashlib

        body = f"#!/bin/sh\n{text}\n".encode()
        target = tmp_path / "floss-build"
        target.write_bytes(body)
        target.chmod(0o755)
        return target, hashlib.sha256(body).hexdigest()

    def test_the_pinned_build_runs_from_a_verified_copy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source, digest = self._script(tmp_path, 'echo "$0"')
        monkeypatch.setattr(tool, "FLOSS_BINARY_SHA256", digest)

        finished = tool._run([str(source)], 30, pinned=source)

        ran = Path(finished.stdout.strip())
        assert ran != source
        assert ran.parent.parent == tmp_path / "staging" / "floss"
        assert not ran.exists(), "the copy goes with its run"

    def test_a_build_changed_after_it_was_checked_is_refused_and_not_run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        marker = tmp_path / "ran"
        source, _digest = self._script(tmp_path, f"touch {marker}")
        monkeypatch.setattr(tool, "FLOSS_BINARY_SHA256", "0" * 64)

        with pytest.raises(tool.NotThePinnedBuild) as refused:
            tool._run([str(source)], 30, pinned=source)

        assert not marker.exists()
        assert str(tmp_path) not in str(refused.value)
        assert list((tmp_path / "staging" / "floss").iterdir()) == []

    def test_a_replaced_file_is_checked_again(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source, digest = self._script(tmp_path, "true")
        monkeypatch.setattr(tool, "FLOSS_BINARY_SHA256", digest)
        assert tool._is_pinned_build(source) is True

        replacement = tmp_path / "other"
        replacement.write_bytes(b"#!/bin/sh\nfalse\n")
        stat = source.stat()
        replacement.chmod(0o755)
        import os

        os.utime(replacement, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        replacement.replace(source)

        assert tool._is_pinned_build(source) is False


class TestTheArgv:
    def test_a_relative_sample_path_reaches_floss_absolute(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        _pe(tmp_path, "rel.dll")

        argv = tool._floss_argv("floss", Path("rel.dll"), 4)

        assert argv[-1] == str(tmp_path / "rel.dll")


class TestOnePinEverywhere:
    """The version and both digests are written in five places and must agree."""

    ROOT = Path(__file__).resolve().parents[3]

    def _text(self, relative: str) -> str:
        return (self.ROOT / relative).read_text(encoding="utf-8")

    def test_the_install_script_pins_the_module_s_build(self) -> None:
        import re

        script = self._text("scripts/install_floss.sh")
        values = dict(re.findall(r'^(VERSION|ZIP_SHA256|BINARY_SHA256)="([^"]+)"$', script, re.M))
        assert values == {
            "VERSION": tool.FLOSS_VERSION,
            "ZIP_SHA256": tool.FLOSS_ZIP_SHA256,
            "BINARY_SHA256": tool.FLOSS_BINARY_SHA256,
        }

    def test_the_image_pins_the_module_s_build(self) -> None:
        import re

        dockerfile = self._text("docker/Dockerfile.backend")
        values = dict(
            re.findall(
                r"^ARG (FLOSS_VERSION|FLOSS_ZIP_SHA256|FLOSS_BINARY_SHA256)=(\S+)$",
                dockerfile,
                re.M,
            )
        )
        assert values == {
            "FLOSS_VERSION": tool.FLOSS_VERSION,
            "FLOSS_ZIP_SHA256": tool.FLOSS_ZIP_SHA256,
            "FLOSS_BINARY_SHA256": tool.FLOSS_BINARY_SHA256,
        }

    @pytest.mark.parametrize(
        "relative, pins",
        [
            ("services/analysis-mcp/README.md", ("version", "zip", "binary")),
            ("docs/configuration.md", ("version", "zip")),
        ],
    )
    def test_the_docs_state_the_same_pin(self, relative: str, pins: tuple[str, ...]) -> None:
        import re

        text = self._text(relative)
        written = {
            "version": set(re.findall(r"floss-(\d+\.\d+\.\d+)", text)),
            "digests": set(re.findall(r"\b[0-9a-f]{64}\b", text)),
        }
        assert written["version"] == {tool.FLOSS_VERSION}
        expected = set()
        if "zip" in pins:
            expected.add(tool.FLOSS_ZIP_SHA256)
        if "binary" in pins:
            expected.add(tool.FLOSS_BINARY_SHA256)
        assert written["digests"] == expected
