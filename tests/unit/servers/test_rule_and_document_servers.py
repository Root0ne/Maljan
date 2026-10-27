"""The rule and document sidecars answer from their program's output, and fail in one shape.

``services/yarax-mcp`` (YARA-X), ``services/oletools-mcp`` (oletools) and
``services/webcrack-mcp`` (webcrack) each serve one program through
``services/cli-sidecar``. No real program runs here: each is stood in for by
a small script on ``PATH`` that writes a fixed answer and the arguments it was
given, so the parsing, the arguments and the failures (a non-zero exit, a
program or rule set that is not there, a format the program does not read, a
path outside the sample roots) are the sidecars' own. The declarations the
platform ships for them are held to the tools each server offers, to the rows
it answers and to the release each image pins. Where oletools or webcrack is
installed on this host, their own reports are run once on files written here.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
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
SERVERS = {"yarax": "yarax-mcp", "oletools": "oletools-mcp", "webcrack": "webcrack-mcp"}


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sidecar = _load("cli_sidecar", SERVICES / "cli-sidecar" / "cli_sidecar.py")
yarax = _load("yarax_mcp_server", SERVICES / "yarax-mcp" / "server.py")
oletools = _load("oletools_mcp_server", SERVICES / "oletools-mcp" / "server.py")
webcrack = _load("webcrack_mcp_server", SERVICES / "webcrack-mcp" / "server.py")
MODULES = {"yarax": yarax, "oletools": oletools, "webcrack": webcrack}


@pytest.fixture
def roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A sample root holding one file, named in ``MALJAN_SAMPLE_ROOTS``; no bound on a run."""
    root = tmp_path / "samples"
    root.mkdir()
    (root / "sample.bin").write_bytes(b"{\\rtf1 not a document\n")
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
def rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A rule directory with one rule file (and a file yr does not read), in ``YARA_X_RULES``."""
    held = tmp_path / "rules"
    (held / "family").mkdir(parents=True)
    (held / "family" / "agent.yar").write_text("rule agent { condition: true }\n")
    (held / "README.md").write_text("not a rule\n")
    monkeypatch.setenv(yarax.RULES_ENV, str(held))
    return held


def _program(
    bin_dir: Path, name: str, *, stdout: str = "", stderr: str = "", code: int = 0
) -> Path:
    """A stand-in for ``name``: writes its arguments beside itself, then answers."""
    out = bin_dir / f"{name}.out"
    err = bin_dir / f"{name}.err"
    out.write_text(stdout, encoding="utf-8")
    err.write_text(stderr, encoding="utf-8")
    script = bin_dir / name
    script.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{bin_dir}/{name}.args"\n'
        f'cat "{out}"\ncat "{err}" >&2\nexit {code}\n',
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
# YARA-X
# ---------------------------------------------------------------------------

YR_JSON = {
    "version": "1.21.0",
    "matches": [
        {
            "rule": "agent_loader",
            "file": "/data/samples/ab/sample.bin",
            "meta": {"author": "ops", "attck": "T1027", "score": 5},
            "tags": ["loader"],
            "strings": [
                {"identifier": "$a", "offset": 3, "match": "hello"},
                {"identifier": "$h", "offset": 9, "match": "\\x00\\xffA"},
            ],
        },
        {"rule": "agent_config", "file": "/data/samples/ab/sample.bin"},
    ],
}
YR_STDERR = (
    "error[E009]: unknown identifier `x`\n"
    " --> /rules/family/bad.yar:1:23\n"
    "  |\n"
    "1 | rule bad { condition: x }\n"
)


class TestYaraX:
    def test_each_matching_rule_is_a_row_with_its_strings(
        self, roots: Path, bin_dir: Path, rules: Path
    ) -> None:
        _program(bin_dir, "yr", stdout=json.dumps(YR_JSON, indent=2), stderr=YR_STDERR)
        answer = _call(yarax.yarax_scan(str(roots / "sample.bin")))
        assert (answer["engine"], answer["engine_version"], answer["rule_files"]) == (
            "yara-x",
            "1.21.0",
            1,
        )
        first, second = answer["matches"]
        # The file's path is the call's own argument, never echoed.
        assert first == {
            key: YR_JSON["matches"][0][key] for key in ("rule", "meta", "tags", "strings")
        }
        assert second == {"rule": "agent_config", "meta": {}, "tags": [], "strings": []}
        assert answer["match_count"] == 2
        assert answer["rules_not_compiled"] == [
            "error[E009]: unknown identifier `x` (/rules/family/bad.yar:1:23)"
        ]
        sample = str((roots / "sample.bin").resolve())
        assert _args(bin_dir, "yr") == [
            "scan",
            "--output-format=json",
            "--print-strings=120",
            "--print-meta",
            "--print-tags",
            "--threads=1",
            "--disable-console-logs",
            "--disable-warnings",
            "--ignore-invalid-rules",
            "--",
            str(rules),
            sample,
        ]

    def test_a_rule_that_does_not_compile_fails_the_call_when_asked(
        self, roots: Path, bin_dir: Path, rules: Path
    ) -> None:
        _program(bin_dir, "yr", stderr=YR_STDERR + "error: 1 error(s) found\n", code=1)
        answer = _call(yarax.yarax_scan(str(roots / "sample.bin"), ignore_invalid_rules=False,
                                        string_chars=40))  # fmt: skip
        code, message = _error(answer)
        assert code == "tool_failed" and message.startswith("yr exited with 1: error[E009]")
        args = _args(bin_dir, "yr")
        assert "--ignore-invalid-rules" not in args and "--print-strings=40" in args

    @pytest.mark.parametrize("chars", [0, -3, True])
    def test_a_string_length_that_is_no_length_is_refused(
        self, roots: Path, bin_dir: Path, rules: Path, chars: Any
    ) -> None:
        _program(bin_dir, "yr", stdout=json.dumps(YR_JSON))
        answer = _call(yarax.yarax_scan(str(roots / "sample.bin"), string_chars=chars))
        assert _error(answer)[0] == "bad_argument"
        assert not (bin_dir / "yr.args").exists()

    def test_no_rule_file_is_an_absence_that_says_where_rules_go(
        self, roots: Path, bin_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _program(bin_dir, "yr", stdout=json.dumps(YR_JSON))
        empty = tmp_path / "empty"
        empty.mkdir()
        (empty / "notes.txt").write_text("rule nope { condition: true }\n")
        monkeypatch.setenv(yarax.RULES_ENV, str(empty))
        answer = _call(yarax.yarax_scan(str(roots / "sample.bin")))
        assert _error(answer) == (
            "missing_dependency",
            f"no YARA rule file (*.yar, *.yara) under {empty}",
        )
        assert "/data/rules" in answer["error"]["remediation"]
        assert not (bin_dir / "yr.args").exists()
        monkeypatch.delenv(yarax.RULES_ENV)
        (cell,) = yarax.capabilities()["tools"]
        assert cell["available"] is False
        assert cell["reason"] == "no YARA rule file (*.yar, *.yara) under YARA_X_RULES (unset)"

    def test_a_missing_program_names_the_pinned_release(
        self, roots: Path, bin_dir: Path, rules: Path
    ) -> None:
        answer = _call(yarax.yarax_scan(str(roots / "sample.bin")))
        assert _error(answer) == ("missing_dependency", "yr is not on PATH")
        assert "YARA-X 1.21.0" in answer["error"]["remediation"]
        _program(bin_dir, "yr")
        (cell,) = yarax.capabilities()["tools"]
        assert (cell["name"], cell["available"]) == ("yarax_scan", True)

    def test_a_path_outside_the_roots_is_refused(
        self, roots: Path, bin_dir: Path, rules: Path, tmp_path: Path
    ) -> None:
        _program(bin_dir, "yr", stdout=json.dumps(YR_JSON))
        outside = tmp_path / "elsewhere.bin"
        outside.write_bytes(b"x")
        answer = _call(yarax.yarax_scan(str(outside)))
        assert _error(answer) == ("path_outside_roots", sidecar.OUTSIDE_ROOTS_MESSAGE)
        assert str(outside) not in json.dumps(answer)


# ---------------------------------------------------------------------------
# oletools
# ---------------------------------------------------------------------------

VBA_REPORT = {
    "container_type": "OLE",
    "encrypted": False,
    "has_vba": True,
    "has_xlm": False,
    "vba_stomping": False,
    "macros": [
        {
            "container": "",
            "stream": "VBA/Module1",
            "module": "Module1.bas",
            "source": "Sub AutoOpen()",
        }
    ],
    "xlm_macros": [],
    "indicators": [
        {"type": "AutoExec", "keyword": "AutoOpen", "description": "Runs when opened"},
        {"type": "Suspicious", "keyword": "Shell", "description": "May run a command"},
    ],
}
RISK_REPORT = {
    "encrypted": False,
    "has_vba": True,
    "suspicious": True,
    "flags": "A-X",
    "autoexec": True,
    "write": False,
    "execute": True,
    "matches": [
        {"flag": "autoexec", "keyword": "AutoOpen"},
        {"flag": "execute", "keyword": "Shell"},
    ],
}
OLEID_REPORT = {
    "indicators": [
        {"id": "vba", "name": "VBA Macros", "value": "Yes", "risk": "Medium", "description": ""}
    ]
}
RTF_REPORT = {
    "objects": [
        {
            "index": 0,
            "start": 53,
            "end": 238,
            "is_ole": True,
            "format_id": 2,
            "class_name": "Package",
            "data_size": 58,
            "is_package": True,
            "filename": "drop.vbs",
            "source_path": "C:\\t\\drop.vbs",
            "temp_path": "C:\\tmp\\drop.vbs",
            "clsid": None,
            "clsid_description": None,
            "payload_sha256": "2c" * 32,
        }
    ]
}
DDE_REPORT = {"encrypted": False, "links": [{"text": 'DDEAUTO c:\\windows\\cmd.exe "/k calc"'}]}


@pytest.fixture
def report(bin_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """``ole_report.py`` stood in for by a script on ``PATH``: give it its answer."""
    monkeypatch.setattr(
        oletools,
        "PROGRAM",
        sidecar.Program(name="oletools", command=("ole-report",), install="install oletools"),
    )

    def answer(document: Any, *, code: int = 0, stderr: str = "") -> None:
        _program(bin_dir, "ole-report", stdout=json.dumps(document), stderr=stderr, code=code)

    return answer


class TestOletools:
    def test_vba_macros_and_their_analysis(self, roots: Path, bin_dir: Path, report: Any) -> None:
        report(VBA_REPORT)
        answer = _call(oletools.ole_vba(str(roots / "sample.bin")))
        assert answer == {"tool": "ole_vba", **VBA_REPORT, "macro_count": 1, "indicator_count": 2}
        sample = str((roots / "sample.bin").resolve())
        assert _args(bin_dir, "ole-report") == ["vba", "--", sample]
        _call(oletools.ole_vba(str(roots / "sample.bin"), deobfuscate=True))
        assert _args(bin_dir, "ole-report") == ["vba", "--deobfuscate", "--", sample]

    def test_each_other_report_answers_under_its_tool(
        self, roots: Path, bin_dir: Path, report: Any
    ) -> None:
        sample = str(roots / "sample.bin")
        for tool, name, document, count in (
            (oletools.ole_macro_risk, "macro_risk", RISK_REPORT, None),
            (oletools.ole_indicators, "indicators", OLEID_REPORT, ("indicator_count", 1)),
            (oletools.rtf_objects, "rtf_objects", RTF_REPORT, ("object_count", 1)),
        ):
            report(document)
            answer = _call(tool(sample))
            assert answer["tool"] == tool.__name__
            assert {k: answer[k] for k in document} == document
            if count:
                assert answer[count[0]] == count[1]
            assert _args(bin_dir, "ole-report")[0] == name

    def test_dde_links_with_the_field_filter_asked_for(
        self, roots: Path, bin_dir: Path, report: Any
    ) -> None:
        report(DDE_REPORT)
        answer = _call(oletools.office_dde(str(roots / "sample.bin"), field_filter="keep_all"))
        assert answer["links"] == DDE_REPORT["links"] and answer["link_count"] == 1
        assert _args(bin_dir, "ole-report")[:3] == ["dde", "--field-filter", "keep_all"]
        refused = _call(oletools.office_dde(str(roots / "sample.bin"), field_filter="--all"))
        assert _error(refused)[0] == "bad_argument"

    def test_a_format_the_report_does_not_read_is_unsupported(
        self, roots: Path, bin_dir: Path, report: Any
    ) -> None:
        said = "the document is RTF, which cannot contain VBA Macros."
        report({"error": {"code": "unsupported_format", "message": said}})
        answer = _call(oletools.ole_vba(str(roots / "sample.bin")))
        assert _error(answer) == ("unsupported_format", f"vba: {said}")
        assert answer["tool"] == "ole_vba"

    def test_a_crashed_report_says_its_words(self, roots: Path, bin_dir: Path, report: Any) -> None:
        report({}, code=1, stderr="Traceback ...\nValueError: bad stream\n")
        answer = _call(oletools.rtf_objects(str(roots / "sample.bin")))
        code, message = _error(answer)
        assert code == "tool_failed" and "ValueError: bad stream" in message

    def test_the_report_is_this_interpreter_on_the_file_beside_the_server(self) -> None:
        command = oletools.PROGRAM.command
        assert command[:2] == (sys.executable, "-I")
        assert Path(command[2]) == SERVICES / "oletools-mcp" / "ole_report.py"
        assert Path(command[2]).is_file()

    @pytest.mark.skipif(
        importlib.util.find_spec("oletools") is not None, reason="oletools is installed here"
    )
    def test_without_oletools_every_tool_is_an_absence(self, roots: Path) -> None:
        answer = _call(oletools.ole_indicators(str(roots / "sample.bin")))
        assert _error(answer) == ("missing_dependency", "oletools is not installed")
        assert "oletools 0.60.2" in answer["error"]["remediation"]
        cells = oletools.capabilities()["tools"]
        assert [c["name"] for c in cells] == list(oletools.TOOLS)
        assert not any(c["available"] for c in cells)


@pytest.mark.skipif(importlib.util.find_spec("oletools") is None, reason="oletools not installed")
def test_the_report_reads_a_document_and_runs_none_of_it(tmp_path: Path) -> None:
    """The real report over a macro written as text and an RTF holding a package and a field."""
    macro = tmp_path / "macro.txt"
    macro.write_text('Sub AutoOpen()\n  Shell "cmd /c x", 1\nEnd Sub\n')
    rtf = tmp_path / "doc.rtf"
    rtf.write_bytes(b'{\\rtf1{\\field{\\*\\fldinst DDEAUTO c:\\\\cmd.exe "/k x"}}}')

    def run(*arguments: str) -> dict[str, Any]:
        script = SERVICES / "oletools-mcp" / "ole_report.py"
        done = subprocess.run(
            [sys.executable, "-I", str(script), *arguments],
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
        return json.loads(done.stdout)

    vba = run("vba", "--", str(macro))
    assert vba["has_vba"] and {"AutoOpen", "Shell"} <= {i["keyword"] for i in vba["indicators"]}
    assert str(macro) not in json.dumps(vba["macros"])
    assert run("macro_risk", "--", str(macro))["flags"] == "A-X"
    assert run("vba", "--", str(rtf))["error"]["code"] == "unsupported_format"
    assert run("rtf_objects", "--", str(macro))["error"]["code"] == "unsupported_format"
    assert run("dde", "--", str(rtf))["links"][0]["text"].startswith("DDEAUTO")


# ---------------------------------------------------------------------------
# webcrack
# ---------------------------------------------------------------------------

WEBCRACK_REPORT = {
    "scripts": [
        {
            "index": 0,
            "language": "vbscript",
            "start": 40,
            "deobfuscated": False,
            "code": "MsgBox 1",
        },
        {
            "index": 1,
            "language": "text/javascript",
            "start": 92,
            "deobfuscated": True,
            "changed": True,
            "code": 'var x = "cmd";',
            "bundle": None,
        },
    ]
}


@pytest.fixture
def deobfuscator(bin_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """``node deobfuscate.mjs`` stood in for by a script on ``PATH``: give it its answer."""
    monkeypatch.setattr(
        webcrack,
        "PROGRAM",
        sidecar.Program(name="webcrack", command=("webcrack-node",), install="install webcrack"),
    )

    def answer(document: Any, *, code: int = 0, stderr: str = "") -> None:
        _program(bin_dir, "webcrack-node", stdout=json.dumps(document), stderr=stderr, code=code)

    return answer


class TestWebcrack:
    def test_each_script_is_a_row_and_the_options_are_flags(
        self, roots: Path, bin_dir: Path, deobfuscator: Any
    ) -> None:
        deobfuscator(WEBCRACK_REPORT)
        answer = _call(webcrack.js_deobfuscate(str(roots / "sample.bin")))
        assert answer == {
            "tool": "js_deobfuscate",
            "scripts": WEBCRACK_REPORT["scripts"],
            "script_count": 2,
            "deobfuscated_count": 1,
        }
        sample = str((roots / "sample.bin").resolve())
        assert _args(bin_dir, "webcrack-node") == [
            "--deobfuscate",
            "--unminify",
            "--unpack",
            "--no-mangle",
            "--",
            sample,
        ]
        _call(webcrack.js_deobfuscate(str(roots / "sample.bin"), deobfuscate=False, unminify=False,
                                      unpack=False, mangle=True))  # fmt: skip
        assert _args(bin_dir, "webcrack-node")[:4] == [
            "--no-deobfuscate",
            "--no-unminify",
            "--no-unpack",
            "--mangle",
        ]

    def test_an_encoded_or_unparsable_script_is_unsupported(
        self, roots: Path, bin_dir: Path, deobfuscator: Any
    ) -> None:
        said = "the script is encoded with JScript.Encode (#@~^), which webcrack does not read"
        deobfuscator({"error": {"code": "unsupported_format", "message": said}})
        answer = _call(webcrack.js_deobfuscate(str(roots / "sample.bin")))
        assert _error(answer) == ("unsupported_format", f"webcrack: {said}")

    def test_a_crash_says_its_words(self, roots: Path, bin_dir: Path, deobfuscator: Any) -> None:
        deobfuscator({}, code=1, stderr="RangeError: Maximum call stack size exceeded\n")
        answer = _call(webcrack.js_deobfuscate(str(roots / "sample.bin")))
        assert _error(answer) == (
            "tool_failed",
            "webcrack exited with 1: RangeError: Maximum call stack size exceeded",
        )

    def test_node_and_webcrack_must_both_be_there(
        self, bin_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Only the stand-ins' directory: this host's own node is not the point.
        monkeypatch.setenv("PATH", str(bin_dir))
        assert webcrack.PROGRAM.absent() == "node is not on PATH"
        _program(bin_dir, "node")
        installed = webcrack.WEBCRACK_PACKAGE.is_file()
        assert webcrack.PROGRAM.absent() == (
            None if installed else "webcrack is not installed beside deobfuscate.mjs"
        )
        assert webcrack.PROGRAM.command == (
            "node",
            str(SERVICES / "webcrack-mcp" / "deobfuscate.mjs"),
        )


@pytest.mark.skipif(
    shutil.which("node") is None or not webcrack.WEBCRACK_PACKAGE.is_file(),
    reason="node and webcrack not installed beside the script",
)
def test_the_script_reads_an_hta_and_evaluates_none_of_it(tmp_path: Path) -> None:
    """The real script over an HTA: its JScript block rewritten, its VBScript block as it is."""
    hta = tmp_path / "a.hta"
    hta.write_text(
        '<html><script language="VBScript">MsgBox "hi"</script>'
        '<script type="text/javascript">var x = "\\x63\\x6d\\x64"; run(x)</script></html>'
    )
    done = subprocess.run(
        ["node", str(SERVICES / "webcrack-mcp" / "deobfuscate.mjs"), "--", str(hta)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    vbscript, jscript = json.loads(done.stdout)["scripts"]
    assert (vbscript["language"], vbscript["deobfuscated"]) == ("vbscript", False)
    assert jscript["deobfuscated"] and '"cmd"' in jscript["code"]


DEOBFUSCATE = SERVICES / "webcrack-mcp" / "deobfuscate.mjs"
# The script's scan, imported without webcrack: each row's language, byte
# offsets and source, and how long the scan took. The first argument is a
# placeholder, so the imported module does not take itself for the program.
SCAN = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const { scripts } = await import(pathToFileURL(process.argv[2]).href);
const bytes = readFileSync(process.argv[3]);
const began = performance.now();
const rows = scripts(bytes);
const ms = performance.now() - began;
process.stdout.write(JSON.stringify({ ms, rows }));
"""
needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
needs_webcrack = pytest.mark.skipif(
    shutil.which("node") is None or not webcrack.WEBCRACK_PACKAGE.is_file(),
    reason="node and webcrack not installed beside the script",
)


def _scan(path: Path) -> dict[str, Any]:
    done = subprocess.run(
        ["node", "--input-type=module", "-e", SCAN, "scan", str(DEOBFUSCATE), str(path)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return json.loads(done.stdout)


@needs_node
class TestTheScriptScan:
    def test_an_unterminated_script_tag_or_block_is_scanned_in_linear_time(
        self, tmp_path: Path
    ) -> None:
        many = tmp_path / "open.hta"
        many.write_bytes(b"<html>" + b"<script>a" * 120_000)
        held = _scan(many)
        assert held["ms"] < 1000
        (row,) = held["rows"]
        assert row["end"] == many.stat().st_size and row["source"].startswith("a<script>")
        tags = tmp_path / "tags.hta"
        tags.write_bytes(b"<html>" + b"<script " * 130_000)
        held = _scan(tags)
        assert held["ms"] < 1000 and held["rows"] == []

    def test_each_rows_offsets_are_bytes_of_the_file(self, tmp_path: Path) -> None:
        # A byte order mark and two-byte letters before the block.
        data = (
            b"\xef\xbb\xbf<html><p>\xc3\xa7\xc3\xb6\xc3\xbc</p>"
            b'<SCRIPT Language="JScript">var s = "\xc3\xbc";</Script>'
            b'<scripting>no</scripting><script type="text/vbscript">MsgBox 1</script></html>'
        )
        hta = tmp_path / "a.hta"
        hta.write_bytes(data)
        jscript, vbscript = _scan(hta)["rows"]
        start = data.index(b"var s")
        assert (jscript["start"], jscript["end"]) == (start, data.index(b"</Script>"))
        assert jscript["language"] == "jscript" and jscript["source"] == 'var s = "\u00fc";'
        assert data[vbscript["start"] : vbscript["end"]] == b"MsgBox 1"
        assert vbscript["language"] == "text/vbscript"

    def test_a_wsf_blocks_cdata_is_read_past(self, tmp_path: Path) -> None:
        wsf = tmp_path / "a.wsf"
        wsf.write_bytes(b'<job><script language="JScript">\n <![CDATA[ x = 1; ]]>\n</script></job>')
        (row,) = _scan(wsf)["rows"]
        assert row["source"] == " x = 1; "

    def test_a_plain_script_is_one_row_of_the_whole_file(self, tmp_path: Path) -> None:
        js = tmp_path / "a.js"
        js.write_bytes(b"\xef\xbb\xbfvar a = '<script>';\n")
        (row,) = _scan(js)["rows"]
        assert (row["start"], row["end"], row["source"]) == (
            0,
            js.stat().st_size,
            "var a = '<script>';\n",
        )

    def test_an_encoded_block_is_unread_on_its_row_alone(self, tmp_path: Path) -> None:
        # Nothing here for webcrack to read, so nothing of it is loaded.
        hta = tmp_path / "a.hta"
        hta.write_bytes(
            b'<html><script language="VBScript">MsgBox 1</script>'
            b'<script language="JScript.Encode">#@~^CAAAAA==W!x^DkKxY</script></html>'
        )
        done = subprocess.run(
            ["node", str(DEOBFUSCATE), "--", str(hta)],
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
        answer = json.loads(done.stdout)
        assert answer["error"]["code"] == "unsupported_format"
        assert "JScript.Encode" in answer["error"]["message"]


@needs_node
def test_empty_blocks_are_rows_without_a_call(tmp_path: Path) -> None:
    """50,000 empty blocks: each a row, webcrack never asked (nor loaded), in moments."""
    hta = tmp_path / "a.hta"
    hta.write_bytes(b"<html>" + b"<script> \n</script>" * 50_000 + b"</html>")
    began = time.monotonic()
    done = subprocess.run(
        ["node", str(DEOBFUSCATE), "--", str(hta)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    assert time.monotonic() - began < 5
    rows = json.loads(done.stdout)["scripts"]
    assert len(rows) == 50_000
    assert not any(row["deobfuscated"] or "error" in row for row in rows)


@needs_webcrack
def test_a_block_nested_past_the_parsers_stack_is_unread_on_its_row(tmp_path: Path) -> None:
    hta = tmp_path / "a.hta"
    deep = b"x = " + b"[" * 60_000 + b"]" * 60_000 + b";"
    hta.write_bytes(b"<html><script>" + deep + b'</script><script>var y = "\\x63";</script></html>')
    done = subprocess.run(
        ["node", str(DEOBFUSCATE), "--", str(hta)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    nested, read = json.loads(done.stdout)["scripts"]
    assert nested["deobfuscated"] is False
    assert nested["error"].startswith("nested deeper than webcrack's parser can follow")
    assert read["deobfuscated"] and '"c"' in read["code"]


@needs_webcrack
def test_an_encoded_block_beside_a_read_one_leaves_the_answer_whole(tmp_path: Path) -> None:
    hta = tmp_path / "a.hta"
    hta.write_bytes(
        b'<html><script language="JScript">#@~^CAAAAA==W!x^DkKxY</script>'
        b'<script>var x = "\\x63\\x6d\\x64";</script></html>'
    )
    done = subprocess.run(
        ["node", str(DEOBFUSCATE), "--", str(hta)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    encoded, read = json.loads(done.stdout)["scripts"]
    assert encoded["deobfuscated"] is False and "JScript.Encode" in encoded["error"]
    assert read["deobfuscated"] and '"cmd"' in read["code"]


# An obfuscator-style string array, its rotator and its decoder.
STRING_ARRAY_SCRIPT = (
    "function _0x4e2a(){var _0x1a=['log','Hello\\x20World!'];_0x4e2a=function(){return _0x1a;};"
    "return _0x4e2a();}\n"
    "function _0x3b1c(_0x2d,_0x5f){var _0x4e=_0x4e2a();return _0x3b1c=function(_0x3b,_0x1c){"
    "_0x3b=_0x3b-0x0;var _0x9a=_0x4e[_0x3b];return _0x9a;},_0x3b1c(_0x2d,_0x5f);}\n"
    "(function(_0xa,_0xb){var _0xc=_0xa();while(!![]){try{var _0xd=parseInt('1');"
    "if(_0xd===_0xb)break;else _0xc['push'](_0xc['shift']());}catch(_0xe){"
    "_0xc['push'](_0xc['shift']());}}}(_0x4e2a,0x1));\n"
    "console[_0x3b1c(0x0)](_0x3b1c(0x1));\n"
)


@needs_webcrack
def test_a_string_array_decoder_call_survives_with_no_sandbox_module(tmp_path: Path) -> None:
    """webcrack, installed without isolated-vm, leaves the decoder calls as written."""
    held = tmp_path / "app"
    shutil.copytree(
        SERVICES / "webcrack-mcp" / "node_modules",
        held / "node_modules",
        ignore=lambda folder, names: ["isolated-vm"] if folder.endswith("node_modules") else [],
    )
    assert not (held / "node_modules" / "isolated-vm").exists()
    shutil.copy(DEOBFUSCATE, held / "deobfuscate.mjs")
    script = tmp_path / "s.js"
    script.write_text(STRING_ARRAY_SCRIPT)
    done = subprocess.run(
        ["node", str(held / "deobfuscate.mjs"), "--", str(script)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    (row,) = json.loads(done.stdout)["scripts"]
    assert row["deobfuscated"]
    # The decoder and its calls are there; no decoded string took a call's place.
    assert "function _0x3b1c(" in row["code"]
    assert re.search(r"console\[_0x3b1c\(0(?:x0)?\)\]\(_0x3b1c\(0?x?1\)\)", row["code"])
    assert 'console.log("Hello World!")' not in row["code"]


ole_report = _load("ole_report_runner", SERVICES / "oletools-mcp" / "ole_report.py")


class _FakeModule:
    """A stand-in module: attributes only."""

    def __init__(self, **attributes: Any) -> None:
        self.__dict__.update(attributes)


class TestTheOleReportNeverRunsWhatItReads:
    def test_the_xlm_emulator_is_off_whatever_olevba_imported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[bool] = []

        class Parser:
            def __init__(self, path: str, data: Any = None, relaxed: bool = True) -> None:
                seen.append(olevba.XLMDEOBFUSCATOR)

            def detect_is_encrypted(self) -> bool:
                return False

        olevba = _FakeModule(
            XLMDEOBFUSCATOR=True, VBA_Parser=Parser, FileOpenError=type("E", (Exception,), {})
        )
        monkeypatch.setitem(sys.modules, "oletools", _FakeModule(olevba=olevba))
        monkeypatch.setitem(sys.modules, "oletools.olevba", olevba)
        sample = tmp_path / "d.doc"
        sample.write_bytes(b"x")
        _parser, encrypted = ole_report._vba_parser(str(sample))
        assert encrypted is False and seen == [False] and olevba.XLMDEOBFUSCATOR is False

    @pytest.mark.parametrize("encrypted", [False, True])
    def test_dde_never_decrypts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, encrypted: bool
    ) -> None:
        def refuse(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("decryption reached")

        crypto = _FakeModule(is_encrypted=lambda _path: encrypted, decrypt=refuse)
        msodde = _FakeModule(
            process_file=lambda _path, _mode: 'DDEAUTO c:\\cmd.exe "/k x"\n',
            process_maybe_encrypted=refuse,
        )
        monkeypatch.setitem(sys.modules, "oletools", _FakeModule(crypto=crypto, msodde=msodde))
        monkeypatch.setitem(sys.modules, "oletools.crypto", crypto)
        monkeypatch.setitem(sys.modules, "oletools.msodde", msodde)
        sample = tmp_path / "d.docx"
        sample.write_bytes(b"x")
        options = ole_report.argparse.Namespace(field_filter="exclude_blacklisted")
        answer = ole_report.dde(str(sample), options)
        if encrypted:
            assert answer == {"encrypted": True, "links": []}
        else:
            assert answer == {"encrypted": False, "links": [{"text": 'DDEAUTO c:\\cmd.exe "/k x"'}]}


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
        # A digest on every base image, never root.
        for base in re.findall(r"^FROM (\S+)", dockerfile, re.MULTILINE):
            assert re.search(r"@sha256:[0-9a-f]{64}$", base), base
        (user,) = re.findall(r"^USER (\S+)$", dockerfile, re.MULTILINE)
        assert user.split(":")[0] != "0" and user != "root"


def test_the_macro_tools_say_no_macro_runs() -> None:
    facts = _declared("oletools")
    for tool in ("ole_vba", "ole_macro_risk"):
        assert "no macro is run" in facts[tool].does_not_show or "no macro run" in (
            facts[tool].does_not_show
        ), tool
    assert "would run the script" in _declared("webcrack")["js_deobfuscate"].does_not_show


def test_yara_x_matches_are_read_as_the_shipped_yara_scans_are(
    roots: Path, bin_dir: Path, rules: Path
) -> None:
    """Signature rules, in yara_scan's row shape, corroborating as the one YARA layer."""
    shipped = builtin_tools("analysis")["yara_scan"]
    facts = _declared("yarax")["yarax_scan"]
    assert (facts.kind, facts.asserts_techniques, facts.source) == (
        shipped.kind,
        True,
        shipped.source,
    )
    assert facts.values == shipped.values and facts.techniques == shipped.techniques
    assert (facts.rows, facts.places) == (shipped.rows, shipped.places)
    _program(bin_dir, "yr", stdout=json.dumps(YR_JSON))
    answer = _call(yarax.yarax_scan(str(roots / "sample.bin")))
    rows = facts.row_values(answer)
    assert [row["rule"] for row in rows] == [["agent_loader"], ["agent_config"]]


def test_the_declared_rows_read_what_the_servers_answer(
    roots: Path, bin_dir: Path, report: Any, deobfuscator: Any
) -> None:
    facts = _declared("oletools")
    sample = str(roots / "sample.bin")
    report(VBA_REPORT)
    rows = facts["ole_vba"].row_values(_call(oletools.ole_vba(sample)))
    assert rows == [
        {"type": ["AutoExec"], "keyword": ["AutoOpen"]},
        {"type": ["Suspicious"], "keyword": ["Shell"]},
    ]
    report(RISK_REPORT)
    rows = facts["ole_macro_risk"].row_values(_call(oletools.ole_macro_risk(sample)))
    assert [row["flag"] for row in rows] == [["autoexec"], ["execute"]]
    report(OLEID_REPORT)
    rows = facts["ole_indicators"].row_values(_call(oletools.ole_indicators(sample)))
    assert rows == [{"indicator": ["vba"], "value": ["Yes"], "risk": ["Medium"]}]
    report(RTF_REPORT)
    (row,) = facts["rtf_objects"].row_values(_call(oletools.rtf_objects(sample)))
    assert row["class_name"] == ["Package"] and row["filename"] == ["drop.vbs"]
    report(DDE_REPORT)
    (row,) = facts["office_dde"].row_values(_call(oletools.office_dde(sample)))
    assert row["instruction"][0].startswith("DDEAUTO")
    deobfuscator(WEBCRACK_REPORT)
    answer = _call(webcrack.js_deobfuscate(sample))
    rows = _declared("webcrack")["js_deobfuscate"].row_values(answer)
    assert [row["language"] for row in rows] == [["vbscript"], ["text/javascript"]]


# ---------------------------------------------------------------------------
# What each image pins
# ---------------------------------------------------------------------------


def _dockerfile(key: str) -> str:
    return (SERVICES / SERVERS[key] / "Dockerfile").read_text(encoding="utf-8")


def test_the_yara_x_image_pins_the_release_its_install_hint_names() -> None:
    dockerfile = _dockerfile("yarax")
    (pinned,) = re.findall(r"^ARG YARA_X_VERSION=(\S+)$", dockerfile, re.MULTILINE)
    assert pinned == yarax.YARA_X_VERSION and pinned in yarax.PROGRAM.install
    # The archive's checksum and the binary's, each checked before it is kept.
    assert len(re.findall(r"sha256sum -c -", dockerfile)) == 2
    assert "YARA_X_RULES=/data/rules" in dockerfile
    assert "--require-hashes" in dockerfile


def test_the_oletools_image_installs_only_hashed_wheels_of_the_pinned_release() -> None:
    dockerfile = _dockerfile("oletools")
    assert "--require-hashes --only-binary=:all:" in dockerfile
    assert "oletools-mcp/requirements.txt" in dockerfile and "ole_report.py" in dockerfile
    pinned = (SERVICES / "oletools-mcp" / "requirements.txt").read_text(encoding="utf-8")
    assert f"oletools=={oletools.OLETOOLS_VERSION} \\" in pinned
    assert oletools.OLETOOLS_VERSION in oletools.PROGRAM.install
    # Every requirement carries a hash, and the MCP SDK is the one every sidecar pins.
    requirements = re.findall(r"^([A-Za-z0-9_.-]+)==(\S+)", pinned, re.MULTILINE)
    hashed = re.findall(r"^[A-Za-z0-9_.-]+==\S+[^\n]*\\\n\s+--hash=sha256:", pinned, re.MULTILINE)
    assert requirements and len(hashed) == len(requirements)
    shared = (SERVICES / "cli-sidecar" / "requirements.txt").read_text(encoding="utf-8")
    assert (
        dict(requirements)["mcp"] == dict(re.findall(r"^(mcp)==(\S+)", shared, re.MULTILINE))["mcp"]
    )


def test_the_webcrack_image_pins_node_and_every_package_by_hash() -> None:
    dockerfile = _dockerfile("webcrack")
    (node,) = re.findall(r"^ARG NODE_VERSION=(\S+)$", dockerfile, re.MULTILINE)
    assert re.findall(r"^ARG NODE_TXZ_SHA256=([0-9a-f]{64})$", dockerfile, re.MULTILINE)
    assert node.split(".")[0] in ("22", "24") and "sha256sum -c -" in dockerfile
    assert "npm ci --ignore-scripts" in dockerfile
    # The sandbox webcrack would evaluate decoders in is not in the image.
    assert "rm -rf node_modules/isolated-vm" in dockerfile
    manifest = json.loads((SERVICES / "webcrack-mcp" / "package.json").read_text())
    assert manifest["dependencies"] == {"webcrack": webcrack.WEBCRACK_VERSION}
    lock = json.loads((SERVICES / "webcrack-mcp" / "package-lock.json").read_text())
    packages = {key: held for key, held in lock["packages"].items() if key}
    assert packages["node_modules/webcrack"]["version"] == webcrack.WEBCRACK_VERSION
    for key, held in packages.items():
        assert held["integrity"].startswith("sha512-"), key
        assert held["resolved"].startswith("https://registry.npmjs.org/"), key
