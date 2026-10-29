"""The identification sidecars answer from their program's output, and fail in one shape.

``services/die-mcp``, ``services/ilspy-mcp`` and ``services/goresym-mcp`` each
wrap one command-line program through ``services/cli-sidecar``. No real
program runs here: each is stood in for by a small script on ``PATH`` that
writes a fixed answer and the arguments it was given, so the parsing, the
arguments, the failures (a non-zero exit, a timeout, a missing program, a path
outside the sample roots) and a cancelled call are the sidecars' own. The
declarations the platform ships for them are held to the tools each server
offers and to the rows it answers.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from maljan.core.config import Settings
from maljan.core.declared_reading import builtin_tools
from maljan.core.tool_declarations import ToolFacts

ROOT = Path(__file__).resolve().parents[3]
SERVICES = ROOT / "services"
SERVERS = {"die": "die-mcp", "ilspy": "ilspy-mcp", "goresym": "goresym-mcp"}


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sidecar = _load("cli_sidecar", SERVICES / "cli-sidecar" / "cli_sidecar.py")
die = _load("die_mcp_server", SERVICES / "die-mcp" / "server.py")
ilspy = _load("ilspy_mcp_server", SERVICES / "ilspy-mcp" / "server.py")
goresym = _load("goresym_mcp_server", SERVICES / "goresym-mcp" / "server.py")
MODULES = {"die": die, "ilspy": ilspy, "goresym": goresym}


@pytest.fixture
def roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A sample root holding one file, named in ``MALJAN_SAMPLE_ROOTS``; no bound on a run."""
    root = tmp_path / "samples"
    root.mkdir()
    (root / "sample.bin").write_bytes(b"MZ not a program\n")
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


def _program(bin_dir: Path, name: str, *, stdout: str = "", stderr: str = "", code: int = 0,
             sleep: float = 0.0) -> Path:  # fmt: skip
    """A stand-in for ``name``: writes its arguments and pid beside itself, then answers."""
    out = bin_dir / f"{name}.out"
    err = bin_dir / f"{name}.err"
    out.write_text(stdout, encoding="utf-8")
    err.write_text(stderr, encoding="utf-8")
    script = bin_dir / name
    script.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{bin_dir}/{name}.args"\n'
        f'echo $$ > "{bin_dir}/{name}.pid"\n'
        + (f"sleep {sleep}\n" if sleep else "")
        + f'cat "{out}"\ncat "{err}" >&2\nexit {code}\n',
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def _args(bin_dir: Path, name: str) -> list[str]:
    return (bin_dir / f"{name}.args").read_text(encoding="utf-8").splitlines()


def _call(coro: Any) -> dict[str, Any]:
    return asyncio.run(coro)


def _error(answer: dict[str, Any]) -> tuple[str, str]:
    return answer["error"]["code"], answer["error"]["message"]


# ---------------------------------------------------------------------------
# Detect It Easy
# ---------------------------------------------------------------------------

DIE_JSON = {
    "detects": [
        {
            "filetype": "PE32",
            "parentfilepart": "Header",
            "values": [
                {
                    "info": "",
                    "name": ".NET Framework",
                    "string": "Library: .NET Framework(CLR v4.0.30319)",
                    "type": "Library",
                    "version": "CLR v4.0.30319",
                },
                {
                    "info": "GUI32",
                    "name": "Microsoft Linker",
                    "string": "Linker: Microsoft Linker(8.0)[GUI32]",
                    "type": "Linker",
                    "version": "8.0",
                },
            ],
        },
        {"filetype": "Binary", "parentfilepart": "Overlay", "values": [{"name": "ZIP"}]},
    ]
}


class TestDetectItEasy:
    def test_each_detected_item_is_a_row_with_where_it_was_found(
        self, roots: Path, bin_dir: Path
    ) -> None:
        # A line of its own before the document is read past.
        _program(bin_dir, "diec", stdout="note: database loaded\n" + json.dumps(DIE_JSON))
        answer = _call(die.die_scan(str(roots / "sample.bin")))
        assert answer["file_types"] == ["PE32", "Binary"]
        assert answer["detection_count"] == 3
        first, _linker, overlay = answer["detections"]
        # The runtime a detection's name is, in the platform's words; none on
        # a detection that names no runtime.
        assert first == {
            "file_type": "PE32",
            "part": "Header",
            **DIE_JSON["detects"][0]["values"][0],
            "runtime": "dotnet",
        }
        assert "runtime" not in _linker
        assert overlay == {"file_type": "Binary", "part": "Overlay", "name": "ZIP"}
        args = _args(bin_dir, "diec")
        assert args == ["--json", "--deepscan", str((roots / "sample.bin").resolve())]

    def test_the_scan_options_are_the_programs_own_flags(self, roots: Path, bin_dir: Path) -> None:
        _program(bin_dir, "diec", stdout=json.dumps({"detects": []}))
        answer = _call(
            die.die_scan(
                str(roots / "sample.bin"),
                deep_scan=False,
                heuristic_scan=True,
                recursive_scan=True,
                all_types=True,
            )
        )
        assert answer["detections"] == [] and answer["detection_count"] == 0
        assert _args(bin_dir, "diec")[:-1] == [
            "--json",
            "--heuristicscan",
            "--recursivescan",
            "--alltypes",
        ]

    def test_a_failed_run_says_the_programs_words(self, roots: Path, bin_dir: Path) -> None:
        _program(bin_dir, "diec", stderr="cannot open the database", code=2)
        answer = _call(die.die_scan(str(roots / "sample.bin")))
        assert _error(answer) == (
            "tool_failed",
            "diec exited with 2: cannot open the database",
        )
        assert answer["tool"] == "die_scan"

    def test_an_answer_with_no_document_is_a_failure(self, roots: Path, bin_dir: Path) -> None:
        _program(bin_dir, "diec", stdout="nothing here\n")
        answer = _call(die.die_scan(str(roots / "sample.bin")))
        assert _error(answer) == ("tool_failed", "diec wrote no JSON document")
        _program(bin_dir, "diec", stdout='{"detects": [')
        answer = _call(die.die_scan(str(roots / "sample.bin")))
        assert _error(answer)[1].startswith("diec wrote JSON that does not parse: ")

    def test_a_banner_with_a_bracket_before_the_document_is_read_past(
        self, roots: Path, bin_dir: Path
    ) -> None:
        _program(bin_dir, "diec", stdout="[!] heuristics on\n" + json.dumps(DIE_JSON))
        answer = _call(die.die_scan(str(roots / "sample.bin")))
        assert answer["detection_count"] == 3

    def test_a_missing_program_is_an_absence_with_the_install_hint(
        self, roots: Path, bin_dir: Path
    ) -> None:
        answer = _call(die.die_scan(str(roots / "sample.bin")))
        assert _error(answer) == ("missing_dependency", "diec is not on PATH")
        assert "Detect It Easy 3.21" in answer["error"]["remediation"]
        manifest = die.capabilities()
        (cell,) = manifest["tools"]
        assert manifest["server"] == "die" and manifest["version"] == die.DIE_VERSION
        assert cell["name"] == "die_scan" and cell["available"] is False
        assert cell["reason"] == "diec is not on PATH"
        assert cell["remediation"] == die.PROGRAM.install

    def test_capabilities_says_what_this_host_runs(self, bin_dir: Path) -> None:
        _program(bin_dir, "diec")
        (cell,) = die.capabilities()["tools"]
        assert cell["available"] is True and cell["reason"] is None
        assert "remediation" not in cell


# ---------------------------------------------------------------------------
# The sample, the clock and the caller
# ---------------------------------------------------------------------------


class TestTheSampleAndTheRun:
    def test_a_path_outside_the_roots_is_refused_before_anything_runs(
        self, roots: Path, bin_dir: Path, tmp_path: Path
    ) -> None:
        _program(bin_dir, "diec", stdout="{}")
        outside = tmp_path / "secret.txt"
        outside.write_text("x")
        # A symbolic link under a root that points out of it lands where it points.
        (roots / "link.bin").symlink_to(outside)
        for path in (str(outside), str(roots / "link.bin"), str(roots / ".." / "secret.txt")):
            answer = _call(die.die_scan(path))
            assert _error(answer) == ("path_outside_roots", sidecar.OUTSIDE_ROOTS_MESSAGE)
            assert str(tmp_path) not in json.dumps(answer)
        assert not (bin_dir / "diec.args").exists()

    def test_a_missing_file_and_an_empty_path_are_said(self, roots: Path, bin_dir: Path) -> None:
        _program(bin_dir, "diec", stdout="{}")
        assert _error(_call(die.die_scan(str(roots / "gone.bin"))))[0] == "no_such_file"
        assert _error(_call(die.die_scan(" ")))[0] == "bad_argument"

    def test_a_nul_in_a_path_or_a_value_is_a_bad_argument(self, roots: Path, bin_dir: Path) -> None:
        _program(bin_dir, "diec", stdout="{}")
        answer = _call(die.die_scan(str(roots / "sample.bin") + "\0x"))
        assert _error(answer) == ("bad_argument", "path holds a NUL character")
        with pytest.raises(sidecar.ToolFailure) as failed:
            sidecar.option_value("type_name", "A\0B")
        assert failed.value.code == "bad_argument"
        assert not (bin_dir / "diec.args").exists()

    def test_a_server_given_no_roots_reads_nothing(
        self, roots: Path, bin_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(sidecar.SAMPLE_ROOTS_ENV)
        _program(bin_dir, "diec", stdout="{}")
        assert _error(_call(die.die_scan(str(roots / "sample.bin"))))[0] == "path_outside_roots"

    def test_a_run_past_the_operators_bound_is_stopped_and_said(
        self, roots: Path, bin_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(sidecar.TIMEOUT_ENV, "0.3")
        _program(bin_dir, "diec", stdout="{}", sleep=30)
        started = time.monotonic()
        answer = _call(die.die_scan(str(roots / "sample.bin")))
        assert time.monotonic() - started < 10
        assert _error(answer) == (
            "timeout",
            f"diec did not finish within 0.3 s ({sidecar.TIMEOUT_ENV})",
        )
        _gone((bin_dir / "diec.pid").read_text().strip())

    def test_no_bound_is_set_unless_the_operator_sets_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for raw, held in (("", None), ("0", None), ("-3", None), ("soon", None), ("12", 12.0)):
            monkeypatch.setenv(sidecar.TIMEOUT_ENV, raw)
            assert sidecar.timeout_seconds() == held

    def test_a_cancelled_call_stops_its_run(self, roots: Path, bin_dir: Path) -> None:
        _program(bin_dir, "diec", stdout="{}", sleep=30)

        async def cancel() -> None:
            task = asyncio.ensure_future(die.die_scan(str(roots / "sample.bin")))
            pid_file = bin_dir / "diec.pid"
            for _ in range(200):
                if pid_file.exists() and pid_file.read_text().strip():
                    break
                await asyncio.sleep(0.02)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        asyncio.run(cancel())
        _gone((bin_dir / "diec.pid").read_text().strip())

    def test_the_program_gets_only_what_it_needs(
        self, roots: Path, bin_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", "not-for-the-program")
        script = bin_dir / "diec"
        script.write_text(f'#!/bin/sh\nenv > "{bin_dir}/env.txt"\necho "{{}}"\n')
        script.chmod(0o755)
        _call(die.die_scan(str(roots / "sample.bin")))
        names = {
            line.split("=", 1)[0]
            for line in (bin_dir / "env.txt").read_text().splitlines()
            if "=" in line
        }
        assert "SETTINGS_ENCRYPTION_KEY" not in names
        assert {"PATH", "HOME", "TMPDIR", "LANG"} <= names


def _gone(pid: str) -> None:
    """The stand-in process is no longer running (it was killed and reaped)."""
    for _ in range(100):
        try:
            os.kill(int(pid), 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    pytest.fail(f"process {pid} still runs")


# ---------------------------------------------------------------------------
# ILSpy
# ---------------------------------------------------------------------------


class TestILSpy:
    @pytest.fixture(autouse=True)
    def _on_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A host that installed the tool globally runs ``ilspycmd`` from PATH.
        monkeypatch.setattr(
            ilspy,
            "PROGRAM",
            sidecar.Program(name="ilspycmd", command=("ilspycmd",), install=ilspy._INSTALL),
        )

    def test_the_type_listing_is_a_row_per_type(self, roots: Path, bin_dir: Path) -> None:
        _program(
            bin_dir,
            "ilspycmd",
            stdout="Class Stealer.Program\nInterface Stealer.IGrab\n\nEnum Stealer.Mode\n",
        )
        answer = _call(ilspy.dotnet_types(str(roots / "sample.bin")))
        assert answer["types"] == [
            {"type_kind": "Class", "name": "Stealer.Program"},
            {"type_kind": "Interface", "name": "Stealer.IGrab"},
            {"type_kind": "Enum", "name": "Stealer.Mode"},
        ]
        assert answer["type_count"] == 3
        sample = str((roots / "sample.bin").resolve())
        assert _args(bin_dir, "ilspycmd") == ["--list", "cisde", "--disable-updatecheck", sample]

    def test_kinds_are_read_as_letters_and_none_is_refused(
        self, roots: Path, bin_dir: Path
    ) -> None:
        _program(bin_dir, "ilspycmd", stdout="Class A\n")
        _call(ilspy.dotnet_types(str(roots / "sample.bin"), kinds="C, e"))
        assert _args(bin_dir, "ilspycmd")[:2] == ["--list", "ce"]
        answer = _call(ilspy.dotnet_types(str(roots / "sample.bin"), kinds="xyz"))
        assert _error(answer)[0] == "bad_argument"

    def test_a_type_is_decompiled_whole_with_what_could_not_be(
        self, roots: Path, bin_dir: Path
    ) -> None:
        code = "public class Program\n{\n\tpublic static void Main() { }\n}\n"
        _program(bin_dir, "ilspycmd", stdout=code, stderr="Main: 1 error\n")
        answer = _call(
            ilspy.dotnet_decompile_type(
                str(roots / "sample.bin"), "Stealer.Program", bundle_entry="app.dll"
            )
        )
        assert answer["source"] == code and answer["language"] == "C#"
        assert answer["decompilation_errors"] == ["Main: 1 error"]
        assert answer["type_name"] == "Stealer.Program"
        sample = str((roots / "sample.bin").resolve())
        assert _args(bin_dir, "ilspycmd") == [
            "--type",
            "Stealer.Program",
            "--ignore-decompilation-errors",
            "--disable-updatecheck",
            "--bundle-entry",
            "app.dll",
            sample,
        ]

    def test_a_member_and_the_whole_assembly_and_il(self, roots: Path, bin_dir: Path) -> None:
        _program(bin_dir, "ilspycmd", stdout=".method public static void Main()\n")
        answer = _call(
            ilspy.dotnet_decompile_member(str(roots / "sample.bin"), "0x06000001", il=True)
        )
        assert answer["language"] == "IL" and answer["member"] == "0x06000001"
        assert _args(bin_dir, "ilspycmd")[:4] == [
            "--member",
            "0x06000001",
            "--ignore-decompilation-errors",
            "--ilcode",
        ]
        _call(ilspy.dotnet_decompile_assembly(str(roots / "sample.bin")))
        assert _args(bin_dir, "ilspycmd")[0] == "--ignore-decompilation-errors"

    def test_a_value_the_program_would_read_as_an_option_is_refused(
        self, roots: Path, bin_dir: Path
    ) -> None:
        _program(bin_dir, "ilspycmd", stdout="")
        for answer in (
            _call(ilspy.dotnet_decompile_type(str(roots / "sample.bin"), "-o/tmp")),
            _call(ilspy.dotnet_metadata_table(str(roots / "sample.bin"), "--help")),
            _call(ilspy.dotnet_types(str(roots / "sample.bin"), bundle_entry="-p")),
        ):
            assert _error(answer)[0] == "bad_argument"
        assert not (bin_dir / "ilspycmd.args").exists()

    def test_resources_and_a_metadata_table(self, roots: Path, bin_dir: Path) -> None:
        _program(bin_dir, "ilspycmd", stdout="app.resources/key\nicon.ico\n")
        answer = _call(ilspy.dotnet_resources(str(roots / "sample.bin")))
        assert answer["resources"] == [{"name": "app.resources/key"}, {"name": "icon.ico"}]
        rows = [{"RID": 1, "Token": "0x02000001", "Name": "<Module>"}]
        _program(bin_dir, "ilspycmd", stdout=json.dumps(rows))
        answer = _call(ilspy.dotnet_metadata_table(str(roots / "sample.bin"), "TypeDef"))
        assert (answer["table"], answer["rows"], answer["row_count"]) == ("TypeDef", rows, 1)
        assert _args(bin_dir, "ilspycmd")[:3] == ["--dump-table", "TypeDef", "--json"]
        _program(bin_dir, "ilspycmd", stdout=json.dumps({"table": "TypeDef", "rows": rows}))
        answer = _call(ilspy.dotnet_metadata_table(str(roots / "sample.bin"), "0x02"))
        assert answer["dump"] == {"table": "TypeDef", "rows": rows}

    def test_the_image_runs_the_tools_assembly_on_the_runtime(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dll = tmp_path / "ilspycmd.dll"
        monkeypatch.setenv("ILSPYCMD_DLL", str(dll))
        held = _load("ilspy_mcp_image", SERVICES / "ilspy-mcp" / "server.py")
        assert held.PROGRAM.command == ("dotnet", str(dll))
        assert held.PROGRAM.env["DOTNET_EnableDiagnostics"] == "0"
        monkeypatch.setenv("PATH", str(tmp_path))
        assert held.PROGRAM.absent() == "dotnet is not on PATH"
        (tmp_path / "dotnet").write_text("#!/bin/sh\n")
        (tmp_path / "dotnet").chmod(0o755)
        assert held.PROGRAM.absent() == "ilspycmd.dll is not installed"
        dll.write_bytes(b"")
        assert held.PROGRAM.absent() is None


# ---------------------------------------------------------------------------
# GoReSym
# ---------------------------------------------------------------------------

GORESYM_JSON = {
    "Version": "go1.21.4",
    "BuildId": "abc/def",
    "Arch": "amd64",
    "OS": "windows",
    "TabMeta": {"VA": 5174784, "Version": "1.20"},
    "BuildInfo": {"GoVersion": "go1.21.4", "Path": "example/agent"},
    "Files": ["/src/agent/main.go"],
    "UserFunctions": [
        {"Start": 0x4A1000, "End": 0x4A1200, "PackageName": "main", "FullName": "main.main"}
    ],
    "StdFunctions": [
        {"Start": 0x401000, "End": 0x401010, "PackageName": "runtime", "FullName": "runtime.gc"}
    ],
    "Types": [{"VA": 1, "Str": "main.Config", "Kind": "Struct"}],
    "Interfaces": [{"VA": 2, "Str": "io.Reader", "Kind": "Interface"}],
    "Strings": [{"Str": "http://c2.example/", "Start": 4202496}],
}


class TestGoReSym:
    def test_functions_and_build_facts(self, roots: Path, bin_dir: Path) -> None:
        _program(bin_dir, "GoReSym", stdout=json.dumps(GORESYM_JSON))
        answer = _call(goresym.go_symbols(str(roots / "sample.bin"), standard_library=True,
                                          file_paths=True, go_version="1.21"))  # fmt: skip
        assert (answer["go_version"], answer["build_id"], answer["os"]) == (
            "go1.21.4",
            "abc/def",
            "windows",
        )
        assert answer["functions"] == [
            {
                "name": "main.main",
                "package": "main",
                "start": "0x4a1000",
                "end": "0x4a1200",
                "standard_library": False,
            },
            {
                "name": "runtime.gc",
                "package": "runtime",
                "start": "0x401000",
                "end": "0x401010",
                "standard_library": True,
            },
        ]
        assert answer["files"] == ["/src/agent/main.go"] and answer["function_count"] == 2
        sample = str((roots / "sample.bin").resolve())
        assert _args(bin_dir, "GoReSym") == ["-d", "-p", "-v", "1.21", sample]

    def test_types_and_strings(self, roots: Path, bin_dir: Path) -> None:
        _program(bin_dir, "GoReSym", stdout=json.dumps(GORESYM_JSON))
        types = _call(goresym.go_types(str(roots / "sample.bin")))
        assert types["types"] == GORESYM_JSON["Types"] and types["interface_count"] == 1
        assert _args(bin_dir, "GoReSym")[:2] == ["-t", "-nofuncs"]
        strings = _call(goresym.go_strings(str(roots / "sample.bin")))
        assert strings["strings"] == GORESYM_JSON["Strings"] and strings["string_count"] == 1
        assert _args(bin_dir, "GoReSym")[:2] == ["-strings", "-nofuncs"]

    def test_a_file_with_no_go_tables_is_another_format(self, roots: Path, bin_dir: Path) -> None:
        said = {"error": "Failed to parse file: no valid pclntab found"}
        _program(bin_dir, "GoReSym", stdout=json.dumps(said), code=1)
        answer = _call(goresym.go_symbols(str(roots / "sample.bin")))
        assert _error(answer) == (
            "unsupported_format",
            "GoReSym: Failed to parse file: no valid pclntab found",
        )

    def test_any_other_failure_is_the_programs_words(self, roots: Path, bin_dir: Path) -> None:
        _program(bin_dir, "GoReSym", stdout=json.dumps({"error": "invalid file: EOF"}), code=1)
        assert _error(_call(goresym.go_types(str(roots / "sample.bin")))) == (
            "tool_failed",
            "GoReSym: invalid file: EOF",
        )
        _program(bin_dir, "GoReSym", stdout="[]", code=0)
        assert _error(_call(goresym.go_strings(str(roots / "sample.bin"))))[0] == "tool_failed"

    def test_a_missing_program_names_the_pinned_release(self, roots: Path, bin_dir: Path) -> None:
        answer = _call(goresym.go_symbols(str(roots / "sample.bin")))
        assert _error(answer) == ("missing_dependency", "GoReSym is not on PATH")
        assert "GoReSym 3.4.1" in answer["error"]["remediation"]
        cells = goresym.capabilities()["tools"]
        assert [c["name"] for c in cells] == ["go_symbols", "go_types", "go_strings"]
        assert not any(c["available"] for c in cells)


# ---------------------------------------------------------------------------
# Serving
# ---------------------------------------------------------------------------


class TestServing:
    def test_a_bind_beyond_loopback_needs_a_token(self) -> None:
        assert sidecar.bind_refusal("127.0.0.1", "") == ""
        assert sidecar.bind_refusal("0.0.0.0", "t" * 32) == ""
        assert "MCP_AUTH_TOKEN is empty" in sidecar.bind_refusal("0.0.0.0", "")

    def test_a_request_without_the_token_is_refused(self) -> None:
        reached: list[str] = []

        async def app(scope: Any, receive: Any, send: Any) -> None:
            reached.append(scope["type"])

        gate = sidecar.BearerGate(app, "s3cret")

        async def ask(headers: list[tuple[bytes, bytes]], kind: str = "http") -> list[Any]:
            sent: list[Any] = []

            async def send(message: Any) -> None:
                sent.append(message)

            await gate({"type": kind, "headers": headers}, None, send)
            return sent

        refused = asyncio.run(ask([(b"authorization", b"Bearer wrong")]))
        assert refused[0]["status"] == 401 and not reached
        assert asyncio.run(ask([]))[0]["status"] == 401
        assert asyncio.run(ask([(b"authorization", b"Bearer s3cret")])) == []
        asyncio.run(ask([], kind="lifespan"))
        assert reached == ["http", "lifespan"]


# ---------------------------------------------------------------------------
# What the platform declares about them
# ---------------------------------------------------------------------------


def _advertised(module: Any) -> dict[str, dict[str, Any]]:
    tools = asyncio.run(module.mcp.list_tools())
    return {tool.name: dict(tool.inputSchema or {}) for tool in tools}


def _declared(key: str) -> dict[str, ToolFacts]:
    # What the server declares of itself, as the platform reads it (kept from its listing).
    return dict(builtin_tools(key))


@pytest.mark.parametrize("key", sorted(SERVERS))
class TestTheDeclarations:
    def test_every_tool_the_server_offers_is_declared_and_no_other(self, key: str) -> None:
        module = MODULES[key]
        advertised = _advertised(module)
        assert set(advertised) == {*module.TOOLS, "capabilities"}
        assert set(_declared(key)) == set(advertised)

    def test_each_declared_path_argument_is_one_the_tool_takes(self, key: str) -> None:
        advertised = _advertised(MODULES[key])
        for tool, facts in _declared(key).items():
            if tool == "capabilities":
                assert facts.kind == "capabilities" and not facts.arguments
                continue
            assert facts.arguments == {"path": "path"}, tool
            assert "path" in advertised[tool]["properties"], tool
            assert "path" in advertised[tool].get("required", []), tool

    def test_each_tool_says_what_it_shows_and_runs_nothing(self, key: str) -> None:
        for tool, facts in _declared(key).items():
            assert facts.read_only, tool
            effects = facts.effects
            assert effects is not None, tool
            assert (effects.executes, effects.network, effects.third_party) == ("no", False, "no")
            assert not facts.discloses_sample
            if tool != "capabilities":
                assert facts.kind and facts.shows and facts.does_not_show, tool

    def test_an_aggregate_names_tools_of_its_own_server(self, key: str) -> None:
        declared = _declared(key)
        for facts in declared.values():
            assert set(facts.aggregate_of) <= set(declared)

    def test_the_block_ships_off_and_reads_the_containers_mount(self, key: str) -> None:
        block = Settings(_env_file=None).mcp.servers[key]
        assert block.enabled is False and block.transport == "streamable-http"
        assert block.reads_staged_sample and block.sample_mount == "/data/samples"
        assert block.tools is None and block.agents == ["static", "reverser"]
        service = SERVERS[key]
        dockerfile = (SERVICES / service / "Dockerfile").read_text(encoding="utf-8")
        (port,) = re.findall(r"MCP_PORT=(\d+)", dockerfile)
        assert block.url == f"http://{service}:{port}/mcp"
        assert f"EXPOSE {port}" in dockerfile
        assert "MALJAN_SAMPLE_ROOTS=/data/samples" in dockerfile


def test_the_declared_rows_read_what_the_servers_answer(roots: Path, bin_dir: Path) -> None:
    """Each row path and value the declaration names finds what the answer holds."""
    _program(bin_dir, "diec", stdout=json.dumps(DIE_JSON))
    answer = _call(die.die_scan(str(roots / "sample.bin")))
    rows = _declared("die")["die_scan"].row_values(answer)
    assert [row.get("name") for row in rows] == [[".NET Framework"], ["Microsoft Linker"], ["ZIP"]]
    assert rows[0]["type"] == ["Library"] and rows[0]["file_type"] == ["PE32"]

    _program(bin_dir, "GoReSym", stdout=json.dumps(GORESYM_JSON))
    facts = _declared("goresym")
    symbols = facts["go_symbols"].row_values(_call(goresym.go_symbols(str(roots / "sample.bin"))))
    assert symbols[0]["name"] == ["main.main"] and symbols[0]["package"] == ["main"]
    types = facts["go_types"].row_values(_call(goresym.go_types(str(roots / "sample.bin"))))
    assert types[0] == {"name": ["main.Config"], "type_kind": ["Struct"]}
    strings = facts["go_strings"].row_values(_call(goresym.go_strings(str(roots / "sample.bin"))))
    assert strings == [{"text": ["http://c2.example/"]}]


def test_the_dotnet_rows_read_what_the_server_answers(
    roots: Path, bin_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        ilspy, "PROGRAM", sidecar.Program(name="ilspycmd", command=("ilspycmd",), install="x")
    )
    _program(bin_dir, "ilspycmd", stdout="Class A.B\n")
    facts = _declared("ilspy")
    rows = facts["dotnet_types"].row_values(_call(ilspy.dotnet_types(str(roots / "sample.bin"))))
    assert rows == [{"name": ["A.B"], "type_kind": ["Class"]}]


@pytest.mark.parametrize(
    ("key", "constant", "argument"),
    [
        ("die", "DIE_VERSION", "DIE_VERSION"),
        ("ilspy", "ILSPYCMD_VERSION", "ILSPYCMD_VERSION"),
        ("goresym", "GORESYM_VERSION", "GORESYM_VERSION"),
    ],
)
def test_each_image_pins_the_release_its_install_hint_names(
    key: str, constant: str, argument: str
) -> None:
    dockerfile = (SERVICES / SERVERS[key] / "Dockerfile").read_text(encoding="utf-8")
    (pinned,) = re.findall(rf"^ARG {argument}=(\S+)$", dockerfile, re.MULTILINE)
    assert pinned == getattr(MODULES[key], constant)
    assert pinned in MODULES[key].PROGRAM.install
    # A digest on every base image, a checksum on every download, never root.
    for base in re.findall(r"^FROM (\S+)", dockerfile, re.MULTILINE):
        assert re.search(r"@sha256:[0-9a-f]{64}$", base), base
    assert re.search(r"sha(256|512)sum -c -", dockerfile)
    (user,) = re.findall(r"^USER (\S+)$", dockerfile, re.MULTILINE)
    assert user.split(":")[0] != "0" and user != "root"
    assert "--require-hashes" in dockerfile
