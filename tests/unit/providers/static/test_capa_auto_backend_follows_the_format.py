"""capa's ``auto`` backend, and the signatures a run loads, are what capa itself picks.

``auto`` used to mean vivisect for every file, and vivisect refuses capa's
``dotnet`` format, so every managed assembly got a capa error instead of
capa's answer. A named backend is still used exactly as configured. The
library signatures went to every run; capa passes them to vivisect for a PE
only, and so does a run here.

The managed assembly here is built from bytes by the test: a PE with a CLR
header and the smallest metadata a reader accepts (a Module row and the
``<Module>`` type). It holds no code and is never run. The shellcode is five
bytes the test writes; the signature files are empty names, never parsed.
"""

from __future__ import annotations

import queue
import struct
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from maljan.core.config import Settings
from maljan.providers.static import capa_yara
from maljan.providers.static.capa_yara import CapaYaraStaticProvider
from maljan.tools import rules as tool

_DOTNET_RULE = """rule:
  meta:
    name: compiled to the .NET platform
    namespace: runtime/dotnet
    authors:
      - maljan
    scopes:
      static: file
      dynamic: file
  features:
    - format: dotnet
"""


def _pad(data: bytes, size: int) -> bytes:
    return data + b"\0" * (-len(data) % size)


def _managed_pe() -> bytes:
    """A 1 KiB PE32 whose CLR header points at a minimal ECMA-335 metadata root."""
    text_rva, file_align, section_align = 0x2000, 0x200, 0x2000
    strings = _pad(b"\0<Module>\0tiny.dll\0", 4)
    table_stream = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, (1 << 0x00) | (1 << 0x02), 0)
    table_stream += struct.pack("<II", 1, 1)  # one Module row, one TypeDef row
    table_stream += struct.pack("<HHHHH", 0, strings.index(b"tiny.dll"), 1, 0, 0)
    table_stream += struct.pack("<IHHHHH", 0, strings.index(b"<Module>"), 0, 0, 1, 1)
    streams = [
        (b"#~", _pad(table_stream, 4)),
        (b"#Strings", strings),
        (b"#US", b"\0" * 4),
        (b"#GUID", bytes(range(16))),
        (b"#Blob", b"\0" * 4),
    ]
    version = _pad(b"v4.0.30319\0", 4)
    offset = 16 + len(version) + 4 + sum(8 + len(_pad(n + b"\0", 4)) for n, _ in streams)
    headers, data = b"", b""
    for name, body in streams:
        headers += struct.pack("<II", offset, len(body)) + _pad(name + b"\0", 4)
        data += body
        offset += len(body)
    metadata = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)) + version
    metadata += struct.pack("<HH", 0, len(streams)) + headers + data
    # The CLR header: its size, runtime 2.5, the metadata, IL only, no entry point.
    cor20 = struct.pack("<IHHIIII", 72, 2, 5, text_rva + 72, len(metadata), 1, 0) + b"\0" * 48
    text = cor20 + metadata
    raw_size = len(_pad(text, file_align))
    directories = [(0, 0)] * 16
    directories[14] = (text_rva, 72)
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        *(0x10B, 8, 0, raw_size, 0, 0, 0, text_rva, 0x4000, 0x10000000),
        *(section_align, file_align, 4, 0, 0, 0, 4, 0, 0),
        *(text_rva + section_align, file_align, 0, 3, 0x8540),
        *(0x100000, 0x1000, 0x100000, 0x1000, 0, 16),
    )
    optional += b"".join(struct.pack("<II", rva, size) for rva, size in directories)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, len(optional), 0x2102)
    section = struct.pack(
        "<8sIIIIIIHHI", b".text", len(text), text_rva, raw_size, file_align, 0, 0, 0, 0, 0x60000020
    )
    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40)
    return _pad(dos + b"PE\0\0" + coff + optional + section, file_align) + _pad(text, file_align)


def _assembly_and_rules(tmp_path: Path) -> tuple[Path, Path]:
    sample = tmp_path / "tiny.dll"
    sample.write_bytes(_managed_pe())
    rules_dir = tmp_path / "capa-rules"
    rules_dir.mkdir()
    (rules_dir / "dotnet.yml").write_text(_DOTNET_RULE, encoding="utf-8")
    return sample, rules_dir


def _worker_answer(
    sample: Path, rules_dir: Path, backend_name: str, signatures: Path | None = None
) -> tuple[str, Any]:
    """The capa child's answer, run in this process: the worker only puts on its queue."""
    answers: queue.Queue[tuple[str, Any]] = queue.Queue()
    signatures_dir = signatures if signatures is not None else rules_dir / "none"
    capa_yara._capa_worker(str(sample), str(rules_dir), str(signatures_dir), backend_name, answers)
    kind, payload = answers.get_nowait()
    while kind == "peak":
        kind, payload = answers.get_nowait()
    return kind, payload


def _signature_dir(tmp_path: Path) -> Path:
    """Three signature file names: capa lists them by suffix and never opens them here."""
    signatures = tmp_path / "capa-signatures"
    signatures.mkdir()
    for name in ("1_a.sig", "2_b.sig", "3_c.sig"):
        (signatures / name).write_bytes(b"")
    return signatures


class TestTheBackendNameReachesTheChild:
    def test_auto_is_handed_on_unresolved_and_a_named_backend_as_its_constant(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        handed: list[str] = []
        monkeypatch.setattr(
            capa_yara,
            "run_capa_document",
            lambda **kwargs: handed.append(kwargs["backend_name"]) or {"rules": {}},
        )
        cfg = Settings(_env_file=None)
        provider = CapaYaraStaticProvider.from_settings(cfg)
        provider._run_capa_bounded(str(tmp_path / "s.exe"), tmp_path)
        cfg.static.capa.backend = "vivisect"
        CapaYaraStaticProvider.from_settings(cfg)._run_capa_bounded(
            str(tmp_path / "s.exe"), tmp_path
        )

        assert handed == ["auto", "BACKEND_VIV"]


class TestTheChoiceIsCapas:
    """capa stands in at its module boundary, so these run where capa is not installed."""

    def _fake_capa(self, monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
        asked: list[tuple[str, str]] = []

        def get_backend_from_cli(args: Any, input_format: str) -> str:
            asked.append((args.backend, input_format))
            return "picked by capa"

        main = types.ModuleType("capa.main")
        main.BACKEND_AUTO = "auto"  # type: ignore[attr-defined]
        main.get_backend_from_cli = get_backend_from_cli  # type: ignore[attr-defined]
        loader = types.ModuleType("capa.loader")
        loader.BACKEND_PEFILE = "pefile"  # type: ignore[attr-defined]
        package = types.ModuleType("capa")
        package.main = main  # type: ignore[attr-defined]
        package.loader = loader  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "capa", package)
        monkeypatch.setitem(sys.modules, "capa.main", main)
        monkeypatch.setitem(sys.modules, "capa.loader", loader)
        return asked

    def test_auto_takes_the_backend_capa_picks_for_the_detected_format(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = self._fake_capa(monkeypatch)

        assert capa_yara._capa_backend(capa_yara._BACKEND_NAMES["auto"], "dotnet") == (
            "picked by capa"
        )
        assert asked == [("auto", "dotnet")]

    def test_a_named_backend_is_used_as_configured_whatever_the_format(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = self._fake_capa(monkeypatch)

        assert capa_yara._capa_backend(capa_yara._BACKEND_NAMES["pefile"], "dotnet") == "pefile"
        assert asked == []

    def test_the_signatures_are_asked_of_capa_with_the_format_and_the_backend(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked: list[tuple[Any, ...]] = []

        def get_signatures_from_cli(args: Any, input_format: str, backend: str) -> list[Path]:
            asked.append((args.signatures, args.is_default_signatures, input_format, backend))
            return [Path("chosen.sig")]

        main = types.ModuleType("capa.main")
        main.get_signatures_from_cli = get_signatures_from_cli  # type: ignore[attr-defined]
        loader = types.ModuleType("capa.loader")
        loader.get_signatures = lambda path: []  # type: ignore[attr-defined]
        package = types.ModuleType("capa")
        package.main = main  # type: ignore[attr-defined]
        package.loader = loader  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "capa", package)
        monkeypatch.setitem(sys.modules, "capa.main", main)
        monkeypatch.setitem(sys.modules, "capa.loader", loader)

        assert capa_yara._capa_signatures(str(tmp_path), "pe", "vivisect") == (
            [Path("chosen.sig")],
            None,
        )
        assert asked == [(tmp_path, False, "pe", "vivisect")]
        # No directory: nothing to choose from, and capa is not asked.
        assert capa_yara._capa_signatures(str(tmp_path / "absent"), "pe", "vivisect") == (
            [],
            capa_yara.LIBRARY_FUNCTIONS_NO_DIRECTORY,
        )
        assert len(asked) == 1


class TestWithCapaInstalled:
    def test_native_code_stays_on_vivisect_and_a_managed_assembly_goes_to_dotnet(self) -> None:
        capa_loader = pytest.importorskip("capa.loader")

        for native in ("pe", "elf", "sc32", "sc64"):
            assert capa_yara._capa_backend("auto", native) == capa_loader.BACKEND_VIV
        assert capa_yara._capa_backend("auto", "dotnet") == capa_loader.BACKEND_DOTNET

    def test_a_managed_assembly_gets_capa_s_answer(self, tmp_path: Path) -> None:
        pytest.importorskip("capa.main")
        sample, rules_dir = _assembly_and_rules(tmp_path)

        answer = tool.capa(
            str(sample),
            timeout_s=120,
            rules_dir=str(rules_dir),
            signatures_dir=str(tmp_path / "none"),
        )

        assert "error" not in answer, answer
        assert answer["meta"]["format"] == "dotnet"
        assert [row["rule"] for row in answer["capabilities"]] == ["compiled to the .NET platform"]
        # A .NET match is located by a metadata token, not by a place in the image.
        assert answer["capabilities"][0]["addresses"] == []
        assert answer["function_starts"] == []
        assert answer["library_functions"] == capa_yara.LIBRARY_FUNCTIONS_NO_DIRECTORY

    def test_a_named_vivisect_backend_still_refuses_a_managed_assembly(
        self, tmp_path: Path
    ) -> None:
        pytest.importorskip("capa.main")
        sample, rules_dir = _assembly_and_rules(tmp_path)

        kind, payload = _worker_answer(sample, rules_dir, capa_yara._BACKEND_NAMES["vivisect"])

        assert kind == "error"
        assert "unexpected format: dotnet" in payload

    def test_auto_in_the_child_reads_the_assembly_with_capa_s_dotnet_extractor(
        self, tmp_path: Path
    ) -> None:
        pytest.importorskip("capa.main")
        sample, rules_dir = _assembly_and_rules(tmp_path)

        kind, document = _worker_answer(sample, rules_dir, capa_yara._BACKEND_NAMES["auto"])

        assert kind == "ok", document
        assert document["meta"]["analysis"]["format"] == "dotnet"
        assert document["meta"]["analysis"]["extractor"] == "DnfileFeatureExtractor"

    def test_a_pe_on_vivisect_gets_the_signatures_and_no_other_format_does(
        self, tmp_path: Path
    ) -> None:
        capa_loader = pytest.importorskip("capa.loader")
        pytest.importorskip("capa.main")
        signatures = str(_signature_dir(tmp_path))

        chosen, _ = capa_yara._capa_signatures(signatures, "pe", capa_loader.BACKEND_VIV)

        assert [path.name for path in chosen] == ["1_a.sig", "2_b.sig", "3_c.sig"]
        for input_format, backend in (
            ("sc32", capa_loader.BACKEND_VIV),
            ("sc64", capa_loader.BACKEND_VIV),
            ("elf", capa_loader.BACKEND_VIV),
            ("dotnet", capa_loader.BACKEND_DOTNET),
            ("pe", capa_loader.BACKEND_PEFILE),
        ):
            assert capa_yara._capa_signatures(signatures, input_format, backend)[0] == []

    def test_a_shellcode_or_managed_run_is_handed_no_signatures(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        capa_loader = pytest.importorskip("capa.loader")
        pytest.importorskip("capa.main")
        assembly, rules_dir = _assembly_and_rules(tmp_path)
        shellcode = tmp_path / "tiny.sc32"
        shellcode.write_bytes(b"\x90\x90\x90\x90\xc3")
        signatures = _signature_dir(tmp_path)
        handed: list[tuple[str, str, list[Path]]] = []
        real = capa_loader.get_extractor

        def spy(
            path: Path, input_format: str, os_: str, backend: str, sigpaths: Any, **kw: Any
        ) -> Any:
            handed.append((input_format, backend, list(sigpaths)))
            return real(path, input_format, os_, backend, sigpaths, **kw)

        monkeypatch.setattr(capa_loader, "get_extractor", spy)
        for sample in (shellcode, assembly):
            kind, payload = _worker_answer(sample, rules_dir, "auto", signatures)
            assert kind == "ok", payload

        assert handed == [
            ("sc32", capa_loader.BACKEND_VIV, []),
            ("dotnet", capa_loader.BACKEND_DOTNET, []),
        ]
