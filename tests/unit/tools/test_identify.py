"""``maljan.tools.identify`` answers about real bytes, not about types.

Every assertion here names a value: the format string, the platform, the
digest, the signing-scheme label. A test that only checked the keys were
present would pass against a tool that reported every file as ``unknown``,
which is the failure mode that actually matters — an identification tool that
never identifies anything looks exactly like a working one from the outside.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path

from maljan.tools import identify

ELF_HEADER = b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + struct.pack("<HH", 2, 0x3E)
PE_STUB = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 62 + b"PE\x00\x00"
MACHO_64_LE = b"\xcf\xfa\xed\xfe"


def _macho_64(commands: bytes, ncmds: int) -> bytes:
    """A 32-byte mach_header_64 followed by its load commands."""
    header = MACHO_64_LE + struct.pack("<IIIIIII", 0x01000007, 0, 2, ncmds, len(commands), 0, 0)
    return header + commands


def _write(tmp_path: Path, name: str, blob: bytes) -> str:
    target = tmp_path / name
    target.write_bytes(blob)
    return str(target)


class TestIdentifyFile:
    def test_an_elf_is_an_elf_on_linux(self, tmp_path: Path) -> None:
        result = identify.identify_file(_write(tmp_path, "s.bin", ELF_HEADER + b"\x00" * 512))
        assert result["file_type"] == "elf"
        assert result["platform"] == "linux"
        assert result["category"] == "executable"
        assert result["magic_hex"].startswith("7f454c46")

    def test_a_pe_is_a_pe_on_windows(self, tmp_path: Path) -> None:
        result = identify.identify_file(_write(tmp_path, "s.exe", PE_STUB + b"\x00" * 512))
        assert result["file_type"] == "pe"
        assert result["platform"] == "windows"

    def test_a_missing_file_is_an_error_and_not_an_exception(self) -> None:
        result = identify.identify_file("/nonexistent/sample.bin")
        assert result["tool"] == "identify_file"
        assert "no such file" in result["error"]


class TestHashes:
    def test_the_three_cryptographic_digests_are_the_real_ones(self, tmp_path: Path) -> None:
        blob = b"maljan test sample" * 64
        result = identify.hashes(_write(tmp_path, "s.bin", blob))
        assert result["sha256"] == hashlib.sha256(blob).hexdigest()
        assert result["md5"] == hashlib.md5(blob, usedforsecurity=False).hexdigest()
        assert result["sha1"] == hashlib.sha1(blob, usedforsecurity=False).hexdigest()

    def test_an_uncomputable_fuzzy_hash_is_absent_rather_than_null(self, tmp_path: Path) -> None:
        """A missing key means "could not compute"; ``None`` would read as a value."""
        result = identify.hashes(_write(tmp_path, "s.txt", b"not a binary"))
        for key in ("ssdeep", "tlsh", "imphash", "telfhash"):
            assert result.get(key) is None
            assert key not in result or result[key]

    def test_imphash_is_absent_for_a_file_that_is_not_a_pe(self, tmp_path: Path) -> None:
        result = identify.hashes(_write(tmp_path, "s.bin", ELF_HEADER + b"\x00" * 512))
        assert "imphash" not in result


class TestSigningInfo:
    def test_an_unsigned_binary_reports_every_scheme_absent(self, tmp_path: Path) -> None:
        result = identify.signing_info(_write(tmp_path, "s.bin", ELF_HEADER + b"\x00" * 512))
        assert result["authenticode"]["present"] is False
        assert result["apk"]["present"] is False
        assert result["macho"]["present"] is False

    def test_a_v1_signed_apk_is_found_from_its_meta_inf_certificate(self, tmp_path: Path) -> None:
        apk = tmp_path / "app.apk"
        with zipfile.ZipFile(apk, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binary manifest")
            archive.writestr("classes.dex", b"dex\n035\x00")
            archive.writestr("META-INF/CERT.RSA", b"\x30\x82 fake pkcs7")
        result = identify.signing_info(str(apk))
        assert result["apk"]["present"] is True
        assert result["apk"]["schemes"] == ["v1"]
        assert result["apk"]["cert_files"] == ["META-INF/CERT.RSA"]

    def test_a_macho_load_command_chain_without_a_signature_says_so(self, tmp_path: Path) -> None:
        # One LC_SEGMENT_64 (0x19) command and nothing else.
        command = struct.pack("<II", 0x19, 16) + b"\x00" * 8
        result = identify.signing_info(_write(tmp_path, "bin", _macho_64(command, 1)))
        assert result["macho"] == {"present": False}

    def test_a_macho_carrying_lc_code_signature_is_reported_as_signed(self, tmp_path: Path) -> None:
        commands = struct.pack("<II", 0x19, 16) + b"\x00" * 8
        commands += struct.pack("<II", 0x1D, 16) + b"\x00" * 8
        result = identify.signing_info(_write(tmp_path, "bin", _macho_64(commands, 2)))
        assert result["macho"]["present"] is True
        assert result["macho"]["load_command"] == "LC_CODE_SIGNATURE"
