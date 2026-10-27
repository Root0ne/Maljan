"""The container and Android sidecars answer from their program's output, and keep what they write.

``services/unblob-mcp`` (unblob) and ``services/jadx-mcp`` (JADX) each serve
one program through ``services/cli-sidecar``. No real program runs here: each
is stood in for by a small script on ``PATH`` that does what its plan beside
it says (writes files, links, a FIFO, a report or a class index) and records
the arguments it was given, so the parsing, the arguments, the failures and
what the servers do with written files are the sidecars' own: unblob's files
land in a directory of their own under the carve root, never beside the
sample; a link is listed by what it names and never followed; only a regular
file of one name is read back, over ``get_artefact``, from beneath the carve
root and nowhere else; an extraction past the upload bound is stopped. The
declarations the platform ships for them are held to the tools each server
offers, to the rows it answers and to the releases each image pins.
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import time
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.tool_pinning import DELIVERY_TOOLS
from maljan.core.builtin_declarations import server_declaration
from maljan.core.config import MCPServerConfig, Settings
from maljan.core.delivery_limits import SAMPLE_UPLOAD_MAX_BYTES
from maljan.core.tool_declarations import ToolFacts
from maljan.pipeline.artefacts import ArtefactStore
from maljan.tools import staging

ROOT = Path(__file__).resolve().parents[3]
SERVICES = ROOT / "services"
SERVERS = {"unblob": "unblob-mcp", "jadx": "jadx-mcp"}


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sidecar = _load("cli_sidecar", SERVICES / "cli-sidecar" / "cli_sidecar.py")
unblob = _load("unblob_mcp_server", SERVICES / "unblob-mcp" / "server.py")
jadx = _load("jadx_mcp_server", SERVICES / "jadx-mcp" / "server.py")
MODULES = {"unblob": unblob, "jadx": jadx}

APK_BYTES = b"PK\x03\x04" + b"\x00" * 60
DEX_BYTES = b"dex\n035\x00" + b"\x00" * 60


@pytest.fixture
def roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A sample root holding an APK-shaped, a dex-shaped and a plain file; no bound on a run."""
    root = tmp_path / "samples"
    root.mkdir()
    (root / "s.bin").write_bytes(b"firmware image, a zip and a gzip inside\n" * 4)
    (root / "a.apk.jadx.kts").write_bytes(APK_BYTES)
    (root / "c.smali").write_bytes(DEX_BYTES)
    monkeypatch.setenv(sidecar.SAMPLE_ROOTS_ENV, str(root))
    monkeypatch.delenv(sidecar.TIMEOUT_ENV, raising=False)
    return root


@pytest.fixture
def bin_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A directory on ``PATH`` the stand-in programs are written to, and nothing else."""
    held = tmp_path / "bin"
    held.mkdir()
    monkeypatch.setenv("PATH", f"{held}{os.pathsep}/usr/bin{os.pathsep}/bin")
    return held


@pytest.fixture
def carve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """unblob's carve root, its keeping time and its bound as shipped."""
    held = tmp_path / "carved"
    monkeypatch.setenv(unblob.CARVE_ROOT_ENV, str(held))
    monkeypatch.delenv(unblob.KEEP_ENV, raising=False)
    monkeypatch.delenv(unblob.UPLOAD_BOUND_ENV, raising=False)
    monkeypatch.setattr(unblob, "WATCH_SECONDS", 0.05)
    return held


def _stand_in(bin_dir: Path, name: str, body: str, plan: dict[str, Any]) -> None:
    """A stand-in for ``name``: a Python script that records its arguments and follows ``plan``."""
    (bin_dir / f"{name}.plan").write_text(json.dumps(plan), encoding="utf-8")
    script = bin_dir / name
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys, time\n"
        "from pathlib import Path\n"
        f"HERE = Path({str(bin_dir)!r})\n"
        f"plan = json.loads((HERE / {name + '.plan'!r}).read_text())\n"
        "args = sys.argv[1:]\n"
        f"(HERE / {name + '.args'!r}).write_text(json.dumps(args))\n"
        "def option(flag):\n"
        "    return args[args.index(flag) + 1] if flag in args else None\n" + body,
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)


def _args(bin_dir: Path, name: str) -> list[str]:
    return json.loads((bin_dir / f"{name}.args").read_text(encoding="utf-8"))


def _call(coro: Any) -> dict[str, Any]:
    return asyncio.run(coro)


def _error(answer: dict[str, Any]) -> tuple[str, str]:
    return answer["error"]["code"], answer["error"]["message"]


# ---------------------------------------------------------------------------
# unblob
# ---------------------------------------------------------------------------

UNBLOB_BODY = """
out = Path(option("--extract-dir"))
sample = args[-1]
top = out / (Path(sample).name + "_extract")
for rel, text in plan.get("files", {}).items():
    (top / rel).parent.mkdir(parents=True, exist_ok=True)
    (top / rel).write_text(text)
for rel, target in plan.get("links", {}).items():
    (top / rel).parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, top / rel)
for rel in plan.get("fifos", []):
    os.mkfifo(top / rel)
for new, old in plan.get("hard_links", []):
    os.link(top / old, top / new)
for new, outside in plan.get("outside_links", []):
    top.mkdir(parents=True, exist_ok=True)
    os.link(outside, top / new)
for raw in plan.get("raw_names", []):
    top.mkdir(parents=True, exist_ok=True)
    with open(os.path.join(os.fsencode(top), raw.encode("latin-1")), "wb") as handle:
        handle.write(b"raw")
if plan.get("flood"):
    top.mkdir(parents=True, exist_ok=True)
    for i in range(plan["flood"]):
        (top / f"flood{i:04d}.bin").write_bytes(b"\\0" * plan.get("flood_size", 400))
    time.sleep(60)
if plan.get("past_the_limit"):
    top.mkdir(parents=True, exist_ok=True)
    with open(top / "cut.bin", "wb", buffering=0) as handle:
        try:
            for _ in range(plan["past_the_limit"]):
                handle.write(b"\\0" * 100)
        except OSError:
            pass
if not plan.get("no_report"):
    text = json.dumps(plan.get("report", []))
    text = text.replace("@TOP@", str(top)).replace("@SAMPLE@", sample)
    Path(option("--report")).write_text(text)
sys.stderr.write(plan.get("stderr", ""))
sys.exit(plan.get("code", 0))
"""


def _unblob(bin_dir: Path, **plan: Any) -> None:
    _stand_in(bin_dir, "unblob", UNBLOB_BODY, plan)


def _task(path: str, *reports: dict[str, Any]) -> dict[str, Any]:
    return {"task": {"path": path, "depth": 0, "blob_id": "b"}, "reports": list(reports)}


SCAN_REPORT = [
    _task(
        "@SAMPLE@",
        {
            "__typename__": "FileMagicReport",
            "magic": "data",
            "mime_type": "application/octet-stream",
        },
        {"__typename__": "StatReport", "path": "@SAMPLE@", "size": 160, "is_dir": False},
        {
            "__typename__": "ChunkReport",
            "id": "1",
            "handler_name": "zip",
            "start_offset": 40,
            "end_offset": 120,
            "size": 80,
            "is_encrypted": False,
            "extraction_reports": [],
        },
        {
            "__typename__": "UnknownChunkReport",
            "id": "2",
            "start_offset": 0,
            "end_offset": 40,
            "size": 40,
            "randomness": {"shannon": {"mean": 3.5, "block_size": 1024}},
        },
    ),
    # A carved chunk's own task: not the sample's, so not a row of the scan.
    _task(
        "@TOP@/40-120.zip",
        {
            "__typename__": "ChunkReport",
            "id": "3",
            "handler_name": "deflate",
            "start_offset": 0,
            "end_offset": 9,
            "size": 9,
            "is_encrypted": False,
            "extraction_reports": [],
        },
    ),
]

EXTRACT_REPORT = [
    _task(
        "@SAMPLE@",
        {
            "__typename__": "FileMagicReport",
            "magic": "data",
            "mime_type": "application/octet-stream",
        },
        {
            "__typename__": "ChunkReport",
            "id": "1",
            "handler_name": "tar",
            "start_offset": 0,
            "end_offset": 160,
            "size": 160,
            "is_encrypted": False,
            "extraction_reports": [
                {
                    "__typename__": "PathTraversalProblem",
                    "problem": "Potential path traversal through tar member",
                    "resolution": "Skipped.",
                    "path": "../../etc/cron.d/x",
                    "extraction_path": "@TOP@/../../etc/cron.d/x",
                },
                {
                    "__typename__": "SpecialFileExtractionProblem",
                    "problem": "Device file",
                    "resolution": "Skipped.",
                    "path": "dev/sda",
                    "mode": 25008,
                    "device": 2048,
                },
            ],
        },
    ),
    _task(
        "@TOP@/etc/config.bin",
        {
            "__typename__": "FileMagicReport",
            "magic": "gzip compressed data",
            "mime_type": "application/gzip",
        },
        {
            "__typename__": "ExtractCommandFailedReport",
            "severity": "WARNING",
            "command": "7z x -y config.bin",
            "stdout": "",
            "stderr": "boom",
            "exit_code": 2,
        },
    ),
    _task(
        "@TOP@/bin/busybox",
        {
            "__typename__": "FileMagicReport",
            "magic": "ELF 32-bit MSB executable",
            "mime_type": "application/x-executable",
        },
    ),
]


class TestTheScan:
    def test_each_chunk_of_the_sample_is_a_row_and_nothing_is_kept(
        self, roots: Path, bin_dir: Path, carve: Path
    ) -> None:
        _unblob(bin_dir, files={"40-120.zip": "zip"}, report=SCAN_REPORT)
        answer = _call(unblob.container_scan(str(roots / "s.bin")))
        assert answer["chunks"] == [
            {
                "file": "",
                "handler": "zip",
                "start_offset": 40,
                "end_offset": 120,
                "size": 80,
                "encrypted": False,
            },
            {
                "file": "",
                "handler": "unknown",
                "start_offset": 0,
                "end_offset": 40,
                "size": 40,
                "entropy": 3.5,
            },
        ]
        assert answer["chunk_count"] == 2 and answer["problems"] == []
        assert answer["file_type"] == {"magic": "data", "mime_type": "application/octet-stream"}
        args = _args(bin_dir, "unblob")
        sample = str((roots / "s.bin").resolve())
        assert args[-2:] == ["--", sample]
        assert args[args.index("--process-num") + 1] == "1"
        assert args[args.index("--depth") + 1] == "1" and "--skip-extraction" in args
        # The chunks were carved into the call's scratch, which went with it.
        assert not Path(args[args.index("--extract-dir") + 1]).exists()
        assert not carve.exists() or list(carve.iterdir()) == []


class TestTheExtraction:
    def test_files_links_and_special_files_are_listed_and_no_link_is_followed(
        self, roots: Path, bin_dir: Path, carve: Path, tmp_path: Path
    ) -> None:
        outside = tmp_path / "outside.txt"
        outside.write_text("the host's own file")
        _unblob(
            bin_dir,
            files={"etc/config.bin": "cfg", "bin/busybox": "\x7fELF"},
            links={"etc/passwd": str(outside), "lib": "/usr/lib", "bin/sh": "busybox"},
            fifos=["etc/initctl"],
            report=EXTRACT_REPORT,
            code=1,
        )
        answer = _call(unblob.container_extract(str(roots / "s.bin")))
        top = "s.bin_extract"
        files = {row["name"]: row for row in answer["files"]}
        assert sorted(files) == [f"{top}/bin/busybox", f"{top}/etc/config.bin"]
        busybox = files[f"{top}/bin/busybox"]
        run_id = busybox["path"].split("/", 1)[0]
        assert busybox == {
            "path": f"{run_id}/{top}/bin/busybox",
            "name": f"{top}/bin/busybox",
            "size": 4,
            "sha256": hashlib.sha256(b"\x7fELF").hexdigest(),
            "magic": "ELF 32-bit MSB executable",
            "mime_type": "application/x-executable",
        }
        assert answer["file_count"] == 2 and answer["bytes_written"] == 7
        # Links by what they name; the host file behind one is never read.
        assert {row["name"]: row["target"] for row in answer["links"]} == {
            f"{top}/etc/passwd": str(outside),
            f"{top}/lib": "/usr/lib",
            f"{top}/bin/sh": "busybox",
        }
        assert answer["special"] == [{"name": f"{top}/etc/initctl", "kind": "fifo"}]
        # Written under the carve root, in a directory of the call's own.
        assert (carve / run_id / top / "etc" / "config.bin").read_text() == "cfg"
        assert sorted(p.name for p in (roots).iterdir()) == ["a.apk.jadx.kts", "c.smali", "s.bin"]
        # What unblob refused or could not do, with places under the extraction.
        reports = [(p["report"], p["file"], p.get("path")) for p in answer["problems"]]
        assert reports == [
            ("PathTraversalProblem", "", "../../etc/cron.d/x"),
            ("SpecialFileExtractionProblem", "", "dev/sda"),
            ("ExtractCommandFailedReport", f"{top}/etc/config.bin", None),
        ]
        failed = answer["problems"][2]
        assert (failed["command"], failed["exit_code"]) == ("7z x -y config.bin", 2)
        assert "stderr" not in failed
        assert answer["chunks"][0]["handler"] == "tar" and "stopped" not in answer
        args = _args(bin_dir, "unblob")
        assert args[args.index("--extract-dir") + 1] == str(carve / run_id)
        assert args[args.index("--depth") + 1] == "10" and "--skip-extraction" not in args

    def test_an_extraction_past_the_upload_bound_is_stopped_and_says_so(
        self, roots: Path, bin_dir: Path, carve: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sample = roots / "s.bin"
        monkeypatch.setenv(unblob.UPLOAD_BOUND_ENV, "1000")
        # The larger of the sample's size and the bound.
        assert unblob.written_bound(str(sample)) == 1000
        monkeypatch.setenv(unblob.UPLOAD_BOUND_ENV, "10")
        assert unblob.written_bound(str(sample)) == sample.stat().st_size
        monkeypatch.setenv(unblob.UPLOAD_BOUND_ENV, "1000")
        _unblob(bin_dir, flood=10, flood_size=400)
        started = time.monotonic()
        answer = _call(unblob.container_extract(str(sample)))
        # Stopped as soon as it was counted, not after the stand-in's minute.
        assert time.monotonic() - started < 30
        assert answer["stopped"].startswith("extraction stopped once the files written passed 1000")
        assert answer["stopped"].endswith("unblob's report of the chunks was not written")
        # Only what fits under the bound is listed; the rest is named, not handed on.
        assert [row["size"] for row in answer["files"]] == [400, 400]
        assert answer["bytes_written"] <= 1000
        assert len(answer["not_handed_on"]) == 8
        assert {row["reason"] for row in answer["not_handed_on"]} == {unblob.PAST_THE_BOUND}
        assert answer["chunks"] == [] and answer["problems"] == []

    def test_a_run_of_too_many_entries_is_stopped_and_says_so(
        self, roots: Path, bin_dir: Path, carve: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(unblob.MAX_ENTRIES_ENV, "5")
        _unblob(bin_dir, flood=20, flood_size=1)
        answer = _call(unblob.container_extract(str(roots / "s.bin")))
        assert "it made more than 5 entries (UNBLOB_MAX_ENTRIES)" in answer["stopped"]

    def test_no_one_file_may_pass_the_bound_and_one_cut_there_is_not_handed_on(
        self, roots: Path, bin_dir: Path, carve: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(unblob.UPLOAD_BOUND_ENV, "1000")
        _unblob(bin_dir, past_the_limit=50, files={"small.txt": "ok"}, report=[_task("@SAMPLE@")])
        answer = _call(unblob.container_extract(str(roots / "s.bin")))
        # The run's file size limit cut the file at the bound; it is named, not handed on.
        cut = carve / answer["files"][0]["path"].split("/", 1)[0] / "s.bin_extract" / "cut.bin"
        assert cut.stat().st_size == 1000
        assert [row["name"] for row in answer["files"]] == ["s.bin_extract/small.txt"]
        assert answer["not_handed_on"] == [
            {"name": "s.bin_extract/cut.bin", "reason": unblob.CUT_AT_THE_BOUND.format(bound=1000)}
        ]
        assert answer["stopped"].startswith("extraction stopped once a file reached 1000 bytes")
        # The report was written, so the answer does not say it was not.
        assert "report" not in answer["stopped"]

    def test_the_first_count_is_at_once(
        self, roots: Path, bin_dir: Path, carve: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counted: list[float] = []
        real = unblob.written

        def counting(top: Path) -> tuple[int, int]:
            counted.append(time.monotonic())
            return real(top)

        monkeypatch.setattr(unblob, "written", counting)
        monkeypatch.setattr(unblob, "WATCH_SECONDS", 30)
        _unblob(bin_dir, report=[_task("@SAMPLE@")])
        started = time.monotonic()
        _call(unblob.container_extract(str(roots / "s.bin")))
        assert counted and counted[0] - started < 5

    def test_the_bound_is_the_platforms_sample_upload_bound_unless_set(
        self, carve: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert unblob.SAMPLE_UPLOAD_MAX_BYTES == SAMPLE_UPLOAD_MAX_BYTES
        assert unblob.upload_bound() == SAMPLE_UPLOAD_MAX_BYTES
        monkeypatch.setenv(unblob.UPLOAD_BOUND_ENV, "not a number")
        assert unblob.upload_bound() == SAMPLE_UPLOAD_MAX_BYTES
        monkeypatch.setenv(unblob.UPLOAD_BOUND_ENV, "")
        assert unblob.upload_bound() == SAMPLE_UPLOAD_MAX_BYTES

    def test_an_extraction_with_no_file_keeps_no_directory(
        self, roots: Path, bin_dir: Path, carve: Path
    ) -> None:
        _unblob(bin_dir, report=[_task("@SAMPLE@")])
        answer = _call(unblob.container_extract(str(roots / "s.bin")))
        assert answer["files"] == [] and answer["file_count"] == 0
        assert list(carve.iterdir()) == []

    def test_an_old_extraction_is_swept_and_one_being_written_is_not(
        self, carve: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        old_id, old = unblob.new_run_directory()
        busy_id, busy = unblob.new_run_directory()
        unblob._writing.discard(old_id)
        monkeypatch.setenv(unblob.KEEP_ENV, "60")
        unblob.sweep(now=time.time() + 30)
        assert old.is_dir() and busy.is_dir()
        unblob.sweep(now=time.time() + 120)
        assert not old.exists() and busy.is_dir()
        unblob._writing.discard(busy_id)

    def test_a_run_without_room_removes_the_oldest_finished_runs_first(
        self, carve: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        now = time.time()
        ids = []
        for age in (300.0, 200.0, 100.0, 10.0):
            run_id, top = unblob.new_run_directory()
            unblob._writing.discard(run_id)
            os.utime(top, (now - age, now - age))
            ids.append(run_id)
        busy_id, _busy = unblob.new_run_directory()
        rooms = iter([(0, 10**9), (0, 10**9), (10**9, 10**9)])
        monkeypatch.setattr(unblob, "_room", lambda root: next(rooms))
        unblob.sweep(now=now, room_for=1)
        # The two oldest went; the third left room; the one written 10 s ago
        # and the one being written were never candidates.
        assert sorted(p.name for p in carve.iterdir()) == sorted([ids[2], ids[3], busy_id])
        unblob._writing.discard(busy_id)

    def test_room_asked_for_is_at_most_all_the_file_system_holds(
        self, carve: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        now = time.time()
        run_id, top = unblob.new_run_directory()
        unblob._writing.discard(run_id)
        os.utime(top, (now - 300, now - 300))
        # A bound larger than the whole tmpfs: what is free when all is free is room.
        monkeypatch.setattr(unblob, "_room", lambda root: (1000, 1000))
        unblob.sweep(now=now, room_for=10**12)
        assert top.is_dir()

    def test_a_run_being_read_is_the_last_to_go(
        self, roots: Path, bin_dir: Path, carve: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _unblob(bin_dir, files={"a.txt": "a"}, report=[_task("@SAMPLE@")])
        answer = _call(unblob.container_extract(str(roots / "s.bin")))
        (row,) = answer["files"]
        top = carve / row["path"].split("/", 1)[0]
        os.utime(top, (1000.0, 1000.0))
        assert "content_b64" in _call(unblob.get_artefact(row["path"]))
        assert top.stat().st_mtime > time.time() - 60
        # Read just now, so making room passes over it.
        monkeypatch.setattr(unblob, "_room", lambda root: (0, 10**9))
        unblob.sweep(room_for=1)
        assert top.is_dir()

    def test_a_finished_run_is_kept_from_when_its_writing_ended(
        self, roots: Path, bin_dir: Path, carve: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _unblob(bin_dir, files={"a.txt": "a"}, report=[_task("@SAMPLE@")])
        real = unblob.new_run_directory

        def early() -> tuple[str, Path]:
            run_id, top = real()
            os.utime(top, (1.0, 1.0))
            return run_id, top

        monkeypatch.setattr(unblob, "new_run_directory", early)
        answer = _call(unblob.container_extract(str(roots / "s.bin")))
        top = carve / answer["files"][0]["path"].split("/", 1)[0]
        assert top.stat().st_mtime > time.time() - 60
        assert not unblob._writing

    def test_no_report_is_a_failure_in_unblobs_words(
        self, roots: Path, bin_dir: Path, carve: Path
    ) -> None:
        _unblob(bin_dir, no_report=True, stderr="Traceback: lief exploded\n", code=1)
        code, message = _error(_call(unblob.container_extract(str(roots / "s.bin"))))
        assert (
            code == "tool_failed" and message == "unblob wrote no report: Traceback: lief exploded"
        )
        assert list(carve.iterdir()) == []

    @pytest.mark.parametrize("depth", [0, -1, True, "3"])
    def test_a_depth_that_is_no_depth_is_refused(
        self, roots: Path, bin_dir: Path, carve: Path, depth: Any
    ) -> None:
        _unblob(bin_dir)
        answer = _call(unblob.container_extract(str(roots / "s.bin"), depth=depth))
        assert _error(answer)[0] == "bad_argument"
        assert not (bin_dir / "unblob.args").exists()

    def test_a_path_outside_the_roots_and_a_missing_program_are_refused(
        self, roots: Path, bin_dir: Path, carve: Path, tmp_path: Path
    ) -> None:
        elsewhere = tmp_path / "elsewhere.bin"
        elsewhere.write_bytes(b"x")
        for tool in (unblob.container_scan, unblob.container_extract):
            assert _error(_call(tool(str(elsewhere))))[0] == "path_outside_roots"
            answer = _call(tool(str(roots / "s.bin")))
            assert answer["error"]["code"] == "missing_dependency"
            assert unblob.UNBLOB_VERSION in answer["error"]["remediation"]


def _hostile_tar() -> bytes:
    """A tar whose members try to leave the extraction: by path, by link, as a device."""
    held = io.BytesIO()
    with tarfile.open(fileobj=held, mode="w") as tar:
        for name, data, kind, link in (
            ("etc/config.txt", b"kept\n", tarfile.REGTYPE, ""),
            ("../../escaped.txt", b"zip slip\n", tarfile.REGTYPE, ""),
            ("etc/passwd", b"", tarfile.SYMTYPE, "/etc/passwd"),
            ("up", b"", tarfile.SYMTYPE, "../../../../"),
            ("up/planted.txt", b"through a link\n", tarfile.REGTYPE, ""),
            ("dev/sda", b"", tarfile.BLKTYPE, ""),
        ):
            info = tarfile.TarInfo(name)
            info.size, info.type, info.linkname = len(data), kind, link
            tar.addfile(info, io.BytesIO(data) if data else None)
    return held.getvalue()


@pytest.mark.skipif(shutil.which("unblob") is None, reason="unblob not installed")
def test_unblob_itself_keeps_every_member_inside_the_extraction(
    roots: Path, carve: Path, tmp_path: Path
) -> None:
    """Where unblob is installed: a hostile tar's members all land inside, or are refused."""
    (roots / "hostile.tar").write_bytes(_hostile_tar())
    before = sorted(p.name for p in tmp_path.iterdir())
    answer = _call(unblob.container_extract(str(roots / "hostile.tar")))
    # Nothing new beside the carve root, and the sample directory as it was.
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted({*before, carve.name})
    assert sorted(p.name for p in roots.iterdir()) == [
        "a.apk.jadx.kts",
        "c.smali",
        "hostile.tar",
        "s.bin",
    ]
    assert not (tmp_path.parent / "escaped.txt").exists()
    run_id = answer["files"][0]["path"].split("/", 1)[0]
    for row in answer["files"]:
        assert (carve / row["path"]).resolve().is_relative_to(carve / run_id)
    for row in answer["links"]:
        target = (carve / run_id / row["name"]).parent / row["target"]
        assert target.resolve().is_relative_to(carve / run_id), row
    refused = {p.get("path") for p in answer["problems"]}
    assert {"../../escaped.txt", "dev/sda"} <= refused


@pytest.mark.skipif(shutil.which("unblob") is None, reason="unblob not installed")
def test_unblob_itself_on_names_links_and_a_bomb(
    roots: Path, carve: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Where unblob is installed: a Latin-1 name, a busybox-style link farm, a gzip bomb."""
    held = io.BytesIO()
    with tarfile.open(fileobj=held, mode="w", format=tarfile.GNU_FORMAT, encoding="latin-1") as tar:
        for name, data, kind, link in (
            ("caf\xe9.txt", b"ab", tarfile.REGTYPE, ""),
            ("bin/busybox", b"\x7fELF", tarfile.REGTYPE, ""),
            ("bin/sh", b"", tarfile.LNKTYPE, "bin/busybox"),
            ("sbin/init", b"", tarfile.LNKTYPE, "bin/busybox"),
        ):
            info = tarfile.TarInfo(name)
            info.size, info.type, info.linkname = len(data), kind, link
            tar.addfile(info, io.BytesIO(data) if data else None)
    (roots / "farm.tar").write_bytes(held.getvalue())
    result = asyncio.run(
        unblob.mcp.call_tool("container_extract", {"path": str(roots / "farm.tar")})
    )
    text = result[0][0].text if isinstance(result, tuple) else result[0].text
    answer = json.loads(text)
    names = {row["name"]: row for row in answer["files"]}
    assert "farm.tar_extract/caf\\xe9.txt" in names
    (busybox,) = [row for row in answer["files"] if row.get("also_named")]
    assert len(busybox["also_named"]) == 2
    for row in answer["files"]:
        assert "content_b64" in _call(unblob.get_artefact(row["path"])), row["name"]
    # A gzip of 64 MiB of zeros past a bound of 1 MiB: nothing larger is kept or listed.
    with gzip.open(roots / "bomb.gz", "wb") as bomb:
        for _ in range(64):
            bomb.write(b"\0" * (1 << 20))
    monkeypatch.setenv(unblob.UPLOAD_BOUND_ENV, str(1 << 20))
    answer = _call(unblob.container_extract(str(roots / "bomb.gz")))
    assert "stopped" in answer and answer["bytes_written"] <= 1 << 20
    assert unblob.written_bytes(carve) <= 2 * (1 << 20)


class TestReadingAWrittenFileBack:
    def _extracted(self, roots: Path, bin_dir: Path, tmp_path: Path) -> dict[str, Any]:
        outside = tmp_path / "secret.txt"
        outside.write_text("host secret")
        _unblob(
            bin_dir,
            files={"big.bin": "A" * 10_000, "payload.bin": "P", "nested/x.txt": "x"},
            links={"escape": str(outside), "updir": "..", "nested/up": "../.."},
            fifos=["pipe"],
            hard_links=[["twin.bin", "payload.bin"]],
            report=[_task("@SAMPLE@")],
        )
        return _call(unblob.container_extract(str(roots / "s.bin")))

    def test_a_file_is_read_in_chunks_with_its_digest(
        self, roots: Path, bin_dir: Path, carve: Path, tmp_path: Path
    ) -> None:
        answer = self._extracted(roots, bin_dir, tmp_path)
        (payload,) = [row for row in answer["files"] if row["name"].endswith("big.bin")]
        first = _call(unblob.get_artefact(payload["path"], 0, 4096))
        assert first["size"] == 10_000 and first["sha256"] == payload["sha256"]
        rest = _call(unblob.get_artefact(payload["path"], 4096, 100_000))
        assert "sha256" not in rest
        data = base64.b64decode(first["content_b64"]) + base64.b64decode(rest["content_b64"])
        assert data == b"A" * 10_000

    def test_the_artefact_store_takes_each_listed_file_in_over_get_artefact(
        self, roots: Path, bin_dir: Path, carve: Path, tmp_path: Path, monkeypatch: Any
    ) -> None:
        monkeypatch.setenv(staging.STAGING_DIR_ENV, str(tmp_path / "staging"))
        answer = self._extracted(roots, bin_dir, tmp_path)

        class _Handle:
            def all_tool_names(self) -> list[str]:
                return ["container_extract", "get_artefact"]

            def tools(self) -> list[Any]:
                class _Tool:
                    name = "get_artefact"

                    async def ainvoke(self, args: dict[str, Any]) -> Any:
                        return await unblob.get_artefact(**args)

                return [_Tool()]

        block = Settings(_env_file=None).mcp.servers["unblob"]
        names = [row["path"] for row in answer["files"]]
        taken, missed = ArtefactStore("job-unblob").take_in_written(
            "unblob", block, names, handle=_Handle(), run_blocking=asyncio.run
        )
        by_name = {row["path"]: row for row in answer["files"]}
        # Each file is taken in by its digest; the hard-linked pair, both of
        # whose names are inside the extraction, once.
        assert sorted(a.name for a in taken) == ["big.bin", "payload.bin", "x.txt"]
        assert missed == []
        for artefact in taken:
            (listed,) = [row for row in by_name.values() if row["name"].endswith(artefact.name)]
            assert artefact.sha256 == listed["sha256"] and artefact.size == listed["size"]
            assert artefact.path.read_bytes() == (carve / listed["path"]).read_bytes()

    @pytest.mark.parametrize(
        "name",
        [
            "escape",
            "updir/s.bin",
            "nested/up/etc/passwd",
            "pipe",
            "nested",
            "missing.bin",
            "../../etc/passwd",
            "payload.bin\0",
        ],
    )
    def test_nothing_but_a_regular_file_beneath_the_carve_root_is_read(
        self, roots: Path, bin_dir: Path, carve: Path, tmp_path: Path, name: str
    ) -> None:
        answer = self._extracted(roots, bin_dir, tmp_path)
        run_id = answer["files"][0]["path"].split("/", 1)[0]
        asked = name if name.startswith("..") else f"{run_id}/s.bin_extract/{name}"
        refused = _call(unblob.get_artefact(asked))
        assert refused["error"]["code"] in (
            "bad_argument",
            "no_such_file",
            "path_outside_roots",
            "unsupported_format",
        ), name
        assert "content_b64" not in refused

    def test_a_file_of_several_names_inside_is_one_row_and_read(
        self, roots: Path, bin_dir: Path, carve: Path, tmp_path: Path
    ) -> None:
        answer = self._extracted(roots, bin_dir, tmp_path)
        (pair,) = [row for row in answer["files"] if "also_named" in row]
        assert {pair["name"], *pair["also_named"]} == {
            "s.bin_extract/payload.bin",
            "s.bin_extract/twin.bin",
        }
        read = _call(unblob.get_artefact(pair["path"]))
        assert base64.b64decode(read["content_b64"]) == b"P"
        # Read again after the server forgot its count: counted afresh.
        unblob._names.clear()
        assert "content_b64" in _call(unblob.get_artefact(pair["path"]))

    def test_a_file_with_a_name_outside_the_extraction_is_not_handed_on(
        self, roots: Path, bin_dir: Path, carve: Path, tmp_path: Path
    ) -> None:
        outside = carve.parent / "outside.bin"
        outside.write_bytes(b"not the sample's")
        _unblob(bin_dir, outside_links=[["stolen", str(outside)]], report=[_task("@SAMPLE@")])
        answer = _call(unblob.container_extract(str(roots / "s.bin")))
        assert answer["files"] == []
        assert answer["not_handed_on"] == [
            {
                "name": "s.bin_extract/stolen",
                "reason": unblob.NAMED_OUTSIDE.format(links=2, inside=1),
            }
        ]
        # Kept while a name is listed, but never read back.
        run_id, top = unblob.new_run_directory()
        (top / "x").mkdir()
        os.link(outside, top / "x" / "stolen")
        unblob._writing.discard(run_id)
        refused = _call(unblob.get_artefact(f"{run_id}/x/stolen"))
        assert refused["error"]["code"] == "path_outside_roots"
        assert "only 1 of them" in refused["error"]["message"]

    def test_a_name_that_is_not_utf8_is_shown_escaped_and_read_by_its_bytes(
        self, roots: Path, bin_dir: Path, carve: Path
    ) -> None:
        _unblob(
            bin_dir,
            raw_names=["caf\xe9-\x01.txt"],
            report=[
                _task(
                    "@TOP@/caf\udce9-\x01.txt",
                    {"__typename__": "FileMagicReport", "magic": "data", "mime_type": "x/y"},
                )
            ],
        )
        sample = str(roots / "s.bin")
        # Through the server's own answer path, which serialises it.
        result = asyncio.run(unblob.mcp.call_tool("container_extract", {"path": sample}))
        text = result[0][0].text if isinstance(result, tuple) else result[0].text
        answer = json.loads(text)
        (row,) = answer["files"]
        assert row["name"] == "s.bin_extract/caf\\xe9-\x01.txt"
        assert row["path"].endswith("/s.bin_extract/caf%E9-%01.txt")
        read = _call(unblob.get_artefact(row["path"]))
        assert base64.b64decode(read["content_b64"]) == b"raw"

    def test_a_chunk_is_at_most_the_platforms_chunk(
        self, roots: Path, bin_dir: Path, carve: Path, tmp_path: Path, monkeypatch: Any
    ) -> None:
        monkeypatch.setattr(unblob, "FETCH_CHUNK_BYTES", 1000)
        answer = self._extracted(roots, bin_dir, tmp_path)
        (big,) = [row for row in answer["files"] if row["name"].endswith("big.bin")]
        read = _call(unblob.get_artefact(big["path"], 0, 1_000_000))
        assert len(base64.b64decode(read["content_b64"])) == 1000 and read["size"] == 10_000

    def test_an_absolute_or_bare_name_is_refused(self, carve: Path) -> None:
        run = "0" * 32
        for name in (
            "/etc/passwd",
            "only-a-run-id",
            "",
            "a/../b",
            f"{run}/%2E%2E/x",
            f"{run}/a%2Fb",
            f"{run}/a%00b",
            f"../{run}/x",
        ):
            assert "content_b64" not in _call(unblob.get_artefact(name)), name

    def test_offsets_and_lengths_are_whole_numbers(self, carve: Path) -> None:
        for offset, length in ((-1, 10), (0, 0), (True, 10), (0, -5)):
            assert _error(_call(unblob.get_artefact("a/b", offset, length)))[0] == "bad_argument"


# ---------------------------------------------------------------------------
# JADX
# ---------------------------------------------------------------------------

JADX_BODY = """
handed = args[-1]
(HERE / "jadx.handed").write_text(json.dumps([Path(handed).name, os.readlink(handed)]))
out = option("--output-dir-src")
if out and "mapping" in plan:
    Path(out).mkdir(parents=True, exist_ok=True)
    (Path(out) / "mapping.json").write_text(json.dumps(plan["mapping"]))
single = option("--single-class-output")
if single and "source" in plan:
    Path(single).write_text(plan["source"])
sys.stdout.write(plan.get("stdout", ""))
sys.stderr.write(plan.get("stderr", ""))
sys.exit(plan.get("code", 0))
"""

MAPPING = {
    "classes": [
        {
            "name": "com.evil.app.MainActivity",
            "alias": "com.evil.app.MainActivity",
            "json": "com/evil/app/MainActivity.json",
            "inner": False,
            "fields": [{"name": "k", "alias": "k"}],
            "methods": [
                {
                    "signature": "onCreate(Landroid/os/Bundle;)V",
                    "name": "onCreate",
                    "alias": "onCreate",
                    "offset": "0x208",
                }
            ],
        },
        {
            "name": "com.evil.app.a",
            "alias": "com.evil.app.Loader",
            "inner": True,
            "fields": [],
            "methods": [],
        },
        {"name": "androidx.core.Util", "alias": "androidx.core.Util", "methods": []},
    ]
}


def _jadx(bin_dir: Path, **plan: Any) -> None:
    _stand_in(bin_dir, "jadx", JADX_BODY, plan)


def _handed(bin_dir: Path) -> list[str]:
    return json.loads((bin_dir / "jadx.handed").read_text(encoding="utf-8"))


class TestJadx:
    def test_each_class_is_a_row_with_its_methods(self, roots: Path, bin_dir: Path) -> None:
        _jadx(bin_dir, mapping=MAPPING, stdout="ERROR - finished with errors, count: 3\n", code=1)
        sample = roots / "a.apk.jadx.kts"
        answer = _call(jadx.android_classes(str(sample)))
        assert answer["class_count"] == 3 and answer["decompilation_errors"] == 3
        first, second, third = answer["classes"]
        assert first == {
            "name": "com.evil.app.MainActivity",
            "inner": False,
            "field_count": 1,
            "methods": [
                {
                    "name": "onCreate",
                    "signature": "onCreate(Landroid/os/Bundle;)V",
                    "dex_offset": "0x208",
                }
            ],
        }
        assert second["alias"] == "com.evil.app.Loader" and second["inner"] is True
        assert third["name"] == "androidx.core.Util" and "alias" not in third
        args = _args(bin_dir, "jadx")
        assert args[: len(jadx._common())] == jadx._common()
        assert args[args.index("--config") + 1] == "none" and "--no-res" in args
        disabled = set(args[args.index("--disable-plugins") + 1].split(","))
        assert {
            "smali-input",
            "java-input",
            "java-convert",
            "xapk-input",
            "apks-input",
            "apkm-input",
            "aab-input",
        } <= disabled
        assert args[args.index("--comments-level") + 1] == "none"
        assert "dex-input" not in disabled
        assert args[args.index("--output-format") + 1] == "json"
        # Handed under a name of the server's own, by the file's bytes, not its upload name.
        assert _handed(bin_dir) == ["input.apk", str(sample.resolve())]

    def test_a_package_keeps_its_classes_alone(self, roots: Path, bin_dir: Path) -> None:
        _jadx(bin_dir, mapping=MAPPING)
        answer = _call(jadx.android_classes(str(roots / "a.apk.jadx.kts"), package="com.evil"))
        assert [row["name"] for row in answer["classes"]] == [
            "com.evil.app.MainActivity",
            "com.evil.app.a",
        ]
        for package in ("com.evil;rm", "-Xfoo", "../x", "com..evil"):
            answer = _call(jadx.android_classes(str(roots / "a.apk.jadx.kts"), package=package))
            assert _error(answer)[0] == "bad_argument", package

    def test_one_class_decompiled_and_a_dex_handed_as_one(self, roots: Path, bin_dir: Path) -> None:
        source = "package com.evil.app;\n\npublic class MainActivity {\n}\n"
        _jadx(bin_dir, source=source)
        sample = roots / "c.smali"
        answer = _call(jadx.android_decompile_class(str(sample), "com.evil.app.MainActivity"))
        assert answer == {
            "tool": "android_decompile_class",
            "language": "Java",
            "class_name": "com.evil.app.MainActivity",
            "source": source,
            "decompilation_errors": 0,
        }
        args = _args(bin_dir, "jadx")
        assert args[args.index("--single-class") + 1] == "com.evil.app.MainActivity"
        assert _handed(bin_dir) == ["input.dex", str(sample.resolve())]

    @pytest.mark.parametrize("name", ["-d/etc", "--config=/x", "a\0b", " "])
    def test_a_class_name_jadx_would_read_as_an_option_is_refused(
        self, roots: Path, bin_dir: Path, name: str
    ) -> None:
        _jadx(bin_dir, source="x")
        answer = _call(jadx.android_decompile_class(str(roots / "c.smali"), name))
        assert _error(answer)[0] == "bad_argument"
        assert not (bin_dir / "jadx.args").exists()

    def test_a_class_jadx_did_not_find_and_a_parse_error_say_their_words(
        self, roots: Path, bin_dir: Path
    ) -> None:
        _jadx(bin_dir, stderr="ERROR - Incorrect arguments: Input class not found: x.Y\n", code=1)
        code, message = _error(_call(jadx.android_decompile_class(str(roots / "c.smali"), "x.Y")))
        assert code == "tool_failed" and "Input class not found: x.Y" in message
        # JADX exits 0 on an argument it cannot parse: no index is the failure.
        _jadx(bin_dir, stdout="Arguments parse error: Expected a command\n")
        code, message = _error(_call(jadx.android_classes(str(roots / "a.apk.jadx.kts"))))
        assert code == "tool_failed" and "Arguments parse error" in message

    def test_a_file_neither_zip_nor_dex_is_unsupported_and_nothing_runs(
        self, roots: Path, bin_dir: Path
    ) -> None:
        _jadx(bin_dir, mapping=MAPPING)
        answer = _call(jadx.android_classes(str(roots / "s.bin")))
        assert _error(answer)[0] == "unsupported_format"
        assert not (bin_dir / "jadx.args").exists()

    def test_a_missing_program_names_the_pinned_release(self, roots: Path, bin_dir: Path) -> None:
        answer = _call(jadx.android_classes(str(roots / "a.apk.jadx.kts")))
        assert answer["error"]["code"] == "missing_dependency"
        assert jadx.JADX_VERSION in answer["error"]["remediation"]


def test_a_run_in_the_callers_directory_leaves_it_to_the_caller(
    roots: Path, bin_dir: Path, tmp_path: Path
) -> None:
    script = bin_dir / "where"
    script.write_text('#!/bin/sh\npwd\nprintf "%s\\n" "$HOME" "$TMPDIR"\ntouch made\n')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    given = tmp_path / "given"
    given.mkdir()
    program = sidecar.Program(name="where", command=("where",), install="x")
    ran = asyncio.run(sidecar.run(program, [], workdir=str(given)))
    assert ran.stdout.decode().split() == [str(given)] * 3
    assert (given / "made").is_file()
    ran = asyncio.run(sidecar.run(program, []))
    scratch = Path(ran.stdout.decode().split()[0])
    assert scratch != given and not scratch.exists()


# ---------------------------------------------------------------------------
# What the platform declares about them
# ---------------------------------------------------------------------------


def _advertised(module: Any) -> dict[str, dict[str, Any]]:
    tools = asyncio.run(module.mcp.list_tools())
    return {tool.name: dict(tool.inputSchema or {}) for tool in tools}


def _declared(key: str) -> dict[str, ToolFacts]:
    return MCPServerConfig(**server_declaration(key)).tool_facts


@pytest.mark.parametrize("key", sorted(SERVERS))
class TestTheDeclarations:
    def test_every_tool_the_server_offers_is_declared_and_no_other(self, key: str) -> None:
        module = MODULES[key]
        advertised = _advertised(module)
        delivery = {"get_artefact"} if key == "unblob" else set()
        assert set(advertised) == {*module.TOOLS, "capabilities", *delivery}
        assert set(_declared(key)) == set(advertised)

    def test_each_declared_path_argument_is_one_the_tool_takes(self, key: str) -> None:
        advertised = _advertised(MODULES[key])
        for tool, facts in _declared(key).items():
            if tool in ("capabilities", "get_artefact"):
                assert not facts.arguments, tool
                continue
            assert facts.arguments == {"path": "path"}, tool
            assert "path" in advertised[tool].get("required", []), tool

    def test_each_tool_says_what_it_shows_and_runs_nothing(self, key: str) -> None:
        for tool, facts in _declared(key).items():
            assert facts.read_only, tool
            effects = facts.effects
            assert effects is not None, tool
            assert (effects.executes, effects.network, effects.third_party) == ("no", False, "no")
            assert not facts.discloses_sample
            if tool not in ("capabilities", "get_artefact"):
                assert facts.kind and facts.shows and facts.does_not_show, tool
                assert "run" in facts.does_not_show, tool

    def test_the_block_ships_off_and_reads_the_containers_mount(self, key: str) -> None:
        block = Settings(_env_file=None).mcp.servers[key]
        assert block.enabled is False and block.transport == "streamable-http"
        assert block.reads_staged_sample and block.sample_mount == "/data/samples"
        agents = ["android_static", "reverser"] if key == "jadx" else ["static", "reverser"]
        assert block.tools is None and block.agents == agents
        service = SERVERS[key]
        dockerfile = (SERVICES / service / "Dockerfile").read_text(encoding="utf-8")
        (port,) = re.findall(r"MCP_PORT=(\d+)", dockerfile)
        assert block.url == f"http://{service}:{port}/mcp"
        assert f"EXPOSE {port}" in dockerfile
        assert "MALJAN_SAMPLE_ROOTS=/data/samples" in dockerfile
        for base in re.findall(r"^FROM (\S+)", dockerfile, re.MULTILINE):
            assert re.search(r"@sha256:[0-9a-f]{64}$", base), base
        (user,) = re.findall(r"^USER (\S+)$", dockerfile, re.MULTILINE)
        assert user.split(":")[0] != "0" and user != "root"


def test_reading_a_file_back_is_a_delivery_primitive_no_model_is_shown() -> None:
    assert "get_artefact" in DELIVERY_TOOLS
    assert _declared("unblob")["get_artefact"].kind == "artefact_delivery"


def test_jadx_leaves_the_manifest_to_apk_info() -> None:
    facts = _declared("jadx")
    assert "apk_info" in facts["android_classes"].does_not_show
    assert set(facts["android_classes"].routed_formats) == {"apk", "dex"}
    shipped = Settings(_env_file=None).mcp.servers["analysis"].tool_facts
    assert "apk_info" in shipped and "android_classes" not in shipped


def test_the_declared_rows_read_what_the_servers_answer(
    roots: Path, bin_dir: Path, carve: Path
) -> None:
    _unblob(bin_dir, files={"40-120.zip": "zip"}, report=SCAN_REPORT)
    facts = _declared("unblob")
    rows = facts["container_scan"].row_values(_call(unblob.container_scan(str(roots / "s.bin"))))
    assert [row["handler"] for row in rows] == [["zip"], ["unknown"]]
    _unblob(bin_dir, files={"bin/busybox": "\x7fELF"}, report=EXTRACT_REPORT)
    answer = _call(unblob.container_extract(str(roots / "s.bin")))
    (row,) = facts["container_extract"].row_values(answer)
    assert row["name"] == ["s.bin_extract/bin/busybox"]
    assert row["magic"] == ["ELF 32-bit MSB executable"]
    _jadx(bin_dir, mapping=MAPPING)
    answer = _call(jadx.android_classes(str(roots / "a.apk.jadx.kts")))
    rows = _declared("jadx")["android_classes"].row_values(answer)
    assert [row["name"] for row in rows] == [
        ["com.evil.app.MainActivity"],
        ["com.evil.app.a"],
        ["androidx.core.Util"],
    ]


# ---------------------------------------------------------------------------
# What each image pins
# ---------------------------------------------------------------------------


def _dockerfile(key: str) -> str:
    return (SERVICES / SERVERS[key] / "Dockerfile").read_text(encoding="utf-8")


def test_the_unblob_image_installs_only_hashed_wheels_of_the_pinned_release() -> None:
    dockerfile = _dockerfile("unblob")
    assert "--require-hashes --only-binary=:all:" in dockerfile
    assert "UNBLOB_CARVE_ROOT=/tmp/carved" in dockerfile
    # sasquatch, the one extractor not from Debian, by the release's checksum.
    assert re.findall(r"^ARG SASQUATCH_DEB_SHA256=([0-9a-f]{64})$", dockerfile, re.MULTILINE)
    assert "sha256sum -c -" in dockerfile
    pinned = (SERVICES / "unblob-mcp" / "requirements.txt").read_text(encoding="utf-8")
    assert f"unblob=={unblob.UNBLOB_VERSION} \\" in pinned
    assert unblob.UNBLOB_VERSION in unblob.PROGRAM.install
    requirements = re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)", pinned, re.MULTILINE)
    hashed = re.findall(r"^[A-Za-z0-9_.-]+==\S+[^\n]*\\\n\s+--hash=sha256:", pinned, re.MULTILINE)
    assert requirements and len(hashed) == len(requirements)
    shared = (SERVICES / "cli-sidecar" / "requirements.txt").read_text(encoding="utf-8")
    shared_pins = dict(re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)", shared, re.MULTILINE))
    for name, version in requirements:
        if name in shared_pins:
            assert version == shared_pins[name], name


def test_the_jadx_image_pins_the_runtime_and_the_release_its_install_hint_names() -> None:
    dockerfile = _dockerfile("jadx")
    (pinned,) = re.findall(r"^ARG JADX_VERSION=(\S+)$", dockerfile, re.MULTILINE)
    assert pinned == jadx.JADX_VERSION and pinned in jadx.PROGRAM.install
    (runtime,) = re.findall(r"^ARG JRE_VERSION=(\S+)$", dockerfile, re.MULTILINE)
    assert runtime.split(".")[0] == "21"
    # The runtime's archive and JADX's, each checked before its contents are kept.
    assert len(re.findall(r"^ARG \w+_SHA256=[0-9a-f]{64}$", dockerfile, re.MULTILINE)) == 2
    assert len(re.findall(r"sha256sum -c -", dockerfile)) == 2
    assert "JADX_JAR=/opt/jadx/jadx.jar" in dockerfile and "--require-hashes" in dockerfile


def test_jadx_keeps_its_temporary_files_and_home_in_the_calls_scratch() -> None:
    options = jadx._JVM_OPTIONS
    assert "-Djava.io.tmpdir=." in options and "-Duser.home=." in options
    assert "-XX:MaxRAMPercentage=50.0" in options
    # A host install's launcher is handed the same through JAVA_OPTS.
    assert jadx.PROGRAM.command == ("jadx",)
    assert jadx.PROGRAM.env["JAVA_OPTS"].split() == list(options[1:4])


def test_a_run_is_held_to_the_limits_its_server_sets(bin_dir: Path, tmp_path: Path) -> None:
    import resource

    script = bin_dir / "limits"
    script.write_text("#!/bin/sh\nulimit -f\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    program = sidecar.Program(name="limits", command=("limits",), install="x")
    if shutil.which("prlimit", path="/usr/bin:/bin"):
        ran = asyncio.run(sidecar.run(program, [], limits={resource.RLIMIT_FSIZE: 1024 * 512}))
        # ulimit -f counts 512-byte blocks.
        assert ran.stdout.decode().strip() == "1024"
    assert unblob.file_size_limit(4096) == {resource.RLIMIT_FSIZE: 4096}


def test_limits_are_set_by_prlimit_before_the_command_and_no_limit_leaves_it_as_it_is() -> None:
    import resource

    command = ("unblob",)
    assert sidecar.limited(command, {resource.RLIMIT_FSIZE: 4096}) == (
        "prlimit",
        "--fsize=4096",
        "--",
        "unblob",
    )
    assert sidecar.limited(command, None) == command and sidecar.limited(command, {}) == command
    with pytest.raises(ValueError, match="no prlimit option"):
        sidecar.limited(command, {resource.RLIMIT_STACK: 1})
    # No preexec hook: nothing runs in the server between the fork and the program.
    assert "preexec_fn" not in (SERVICES / "cli-sidecar" / "cli_sidecar.py").read_text()


def test_a_limited_run_without_prlimit_is_a_missing_dependency(
    bin_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import resource

    script = bin_dir / "tool"
    script.write_text("#!/bin/sh\necho ran\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(bin_dir))
    program = sidecar.Program(name="tool", command=("tool",), install="x")
    with pytest.raises(sidecar.ToolFailure) as caught:
        asyncio.run(sidecar.run(program, [], limits={resource.RLIMIT_FSIZE: 10}))
    assert caught.value.code == "missing_dependency" and "util-linux" in caught.value.remediation
    # Without limits the same program runs as the other sidecars run theirs.
    assert asyncio.run(sidecar.run(program, [])).stdout == b"ran\n"


def test_the_unblob_image_carries_prlimit() -> None:
    assert re.search(r"\butil-linux\b", _dockerfile("unblob"))
