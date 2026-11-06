"""The judge is never given another target's md5, sha1 or size as the sample's.

The judge's identity block took the md5, sha1 and size from the sandbox
report's own file block, as facts about the sample with no caveat, even where
the run had marked the report as naming another target (T-322). A marked
report's block is now left out, and the values are read from the sample's own
bytes, only where they still read the intake SHA-256. An unmarked report gives
the judge the same block, byte for byte. Synthetic bytes only; no sample is
run.
"""

from __future__ import annotations

import copy
import hashlib
import logging
from pathlib import Path
from typing import Any

import pytest

from malspark.agents.judge_agent import (
    ROUTER_ONLY_IDENTITY_HEADER,
    SAMPLE_BYTES_IDENTITY_HEADER,
    SAMPLE_IDENTITY_HEADER,
    sample_identity_block,
)
from malspark.analysis.sample_integrity import (
    file_sha256,
    sample_fingerprints,
    sandbox_target_record,
)
from malspark.pipeline import sandbox_status as status
from malspark.pipeline.nodes import _sample_identity

BYTES = b"MZ synthetic sample bytes, never run\x00" * 64
INTAKE = hashlib.sha256(BYTES).hexdigest()
OTHER = hashlib.sha256(b"some other bytes").hexdigest()
# The target's own file block, as a sandbox reports it.
TARGET_MD5, TARGET_SHA1, TARGET_SIZE = "b" * 32, "c" * 40, 4096
REPORT: dict[str, Any] = {
    "target": {
        "sha256": OTHER,
        "file": {"md5": TARGET_MD5, "sha1": TARGET_SHA1, "size": TARGET_SIZE},
    },
    "behavior": {},
}


def _marked() -> dict[str, Any]:
    record = sandbox_target_record(INTAKE, OTHER, provider="lab", task_id="7")
    assert record is not None
    return {**copy.deepcopy(REPORT), status.TARGET_KEY: status.target_mark(record)}


def _state(report: Any, sample_path: Any = None) -> dict[str, Any]:
    return {
        "file_hash": INTAKE,
        "file_name": "s.exe",
        "file_type": "pe",
        "platform": "windows",
        "sandbox_report": report,
        "sample_path": sample_path,
    }


def _sample(tmp_path: Path, data: bytes = BYTES) -> str:
    path = tmp_path / "s.exe"
    path.write_bytes(data)
    return str(path)


class TestAMarkedReport:
    def test_none_of_the_target_s_block_is_the_sample_s(self, tmp_path: Path) -> None:
        identity = _sample_identity(_state(_marked(), _sample(tmp_path)))
        block = sample_identity_block(identity)

        for value in (TARGET_MD5, TARGET_SHA1, str(TARGET_SIZE)):
            assert value not in block
        assert identity["sha256"] == INTAKE

    def test_the_sample_s_own_bytes_give_the_values(self, tmp_path: Path) -> None:
        identity = _sample_identity(_state(_marked(), _sample(tmp_path)))

        assert identity["md5"] == hashlib.md5(BYTES, usedforsecurity=False).hexdigest()
        assert identity["sha1"] == hashlib.sha1(BYTES, usedforsecurity=False).hexdigest()
        assert identity["size_bytes"] == len(BYTES)

    def test_a_copy_that_is_not_the_intake_bytes_gives_no_hash(self, tmp_path: Path) -> None:
        changed = b"other bytes in the sample's place"
        identity = _sample_identity(_state(_marked(), _sample(tmp_path, changed)))

        assert "md5" not in identity
        assert "sha1" not in identity
        # Nor the changed copy's size, read off the disk.
        assert "size_bytes" not in identity

    def test_no_sample_on_disk_gives_no_hash_and_no_size(self) -> None:
        identity = _sample_identity(_state(_marked(), None))

        assert set(identity) == {
            "sha256",
            "file_name",
            "file_type",
            "platform",
            status.IDENTITY_SOURCE_KEY,
        }
        assert identity[status.IDENTITY_SOURCE_KEY] == status.FROM_ROUTER_ONLY

    @pytest.mark.parametrize("copy_is", ["missing", "changed"])
    def test_no_row_from_the_bytes_is_headed_by_the_router_alone(
        self, tmp_path: Path, copy_is: str
    ) -> None:
        path = None if copy_is == "missing" else _sample(tmp_path, b"other bytes")
        identity = _sample_identity(_state(_marked(), path))
        block = sample_identity_block(identity)

        assert "size_bytes" not in identity
        assert block.startswith(f"=== {ROUTER_ONLY_IDENTITY_HEADER} ===\n")
        assert "file block" not in block
        assert "own bytes" not in block
        # The provenance picks the header; it is never a row of the block.
        assert status.IDENTITY_SOURCE_KEY not in block
        assert status.FROM_ROUTER_ONLY not in block

    def test_the_block_says_its_values_are_the_sample_s_own_bytes(self, tmp_path: Path) -> None:
        identity = _sample_identity(_state(_marked(), _sample(tmp_path)))
        block = sample_identity_block(identity)

        assert block.startswith(f"=== {SAMPLE_BYTES_IDENTITY_HEADER} ===\n")
        assert SAMPLE_IDENTITY_HEADER not in block
        assert "sandbox's own file block" not in block
        # The provenance picks the header; it is never a row of the block.
        assert status.IDENTITY_SOURCE_KEY not in block
        assert status.FROM_SAMPLE_BYTES not in block

    def test_each_judge_turn_reads_the_copy_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import malspark.analysis.sample_integrity as integrity

        reads: list[str] = []
        real = integrity._file_digests

        def _counted(*args: Any) -> Any:
            reads.append(str(args[0]))
            return real(*args)

        monkeypatch.setattr(integrity, "_file_digests", _counted)
        monkeypatch.setattr(integrity, "_FINGERPRINTS", {})
        state = _state(_marked(), _sample(tmp_path))

        first = _sample_identity(state)
        for _ in range(5):
            assert _sample_identity(state) == first
        assert len(reads) == 1

        # Other bytes written in its place are read again.
        Path(state["sample_path"]).write_bytes(b"x" * 7)
        assert "md5" not in _sample_identity(state)
        assert len(reads) == 2

    def test_a_mark_of_a_value_that_is_not_a_sha256_still_drops_the_block(
        self, tmp_path: Path
    ) -> None:
        record = sandbox_target_record(INTAKE, "not a hash")
        assert record is not None
        report = {**copy.deepcopy(REPORT), status.TARGET_KEY: status.target_mark(record)}

        identity = _sample_identity(_state(report, None))

        assert TARGET_MD5 not in identity.values()
        assert TARGET_SIZE not in identity.values()


class TestAnUnmarkedReport:
    @pytest.mark.parametrize("on_disk", [False, True])
    def test_the_block_is_byte_for_byte_the_sandbox_s(self, tmp_path: Path, on_disk: bool) -> None:
        state = _state(copy.deepcopy(REPORT), _sample(tmp_path) if on_disk else None)

        identity = _sample_identity(state)

        assert identity == {
            "sha256": INTAKE,
            "file_name": "s.exe",
            "file_type": "pe",
            "platform": "windows",
            "md5": TARGET_MD5,
            "sha1": TARGET_SHA1,
            "size_bytes": TARGET_SIZE,
        }
        assert sample_identity_block(identity) == (
            "=== SAMPLE IDENTITY (established by the router and the sandbox's own file "
            "block, not by analysis) ===\n"
            f"sha256: {INTAKE}\nsha1: {TARGET_SHA1}\nmd5: {TARGET_MD5}\n"
            'file name (as submitted): "s.exe"\n'
            f"size (bytes): {TARGET_SIZE}\nfile type: pe\nplatform: windows"
        )

    def test_no_report_takes_the_size_from_disk_as_before(self, tmp_path: Path) -> None:
        identity = _sample_identity(_state(None, _sample(tmp_path)))

        assert identity["size_bytes"] == len(BYTES)
        assert "md5" not in identity


class TestTheFingerprints:
    def test_one_pass_reads_the_intake_hash(self, tmp_path: Path) -> None:
        path = _sample(tmp_path)

        assert sample_fingerprints(path, INTAKE.upper())["size_bytes"] == len(BYTES)
        assert file_sha256(path) == (INTAKE, "")
        assert file_sha256(path, len(BYTES) + 1)[0] == ""

    def test_the_intake_size_bounds_the_read(self, tmp_path: Path) -> None:
        path = _sample(tmp_path)

        assert sample_fingerprints(path, INTAKE, len(BYTES))["size_bytes"] == len(BYTES)
        assert sample_fingerprints(path, INTAKE, len(BYTES) - 1) == {}

    @pytest.mark.parametrize("path", [None, "", 7, "/nonexistent/malspark/sample"])
    def test_nothing_read_is_nothing_given(self, path: Any) -> None:
        assert sample_fingerprints(path, INTAKE) == {}

    def test_a_link_in_the_sample_s_place_is_not_followed(self, tmp_path: Path) -> None:
        real = _sample(tmp_path)
        link = tmp_path / "link.exe"
        link.symlink_to(real)

        assert sample_fingerprints(str(link), INTAKE) == {}


# A report whose target file block and guest name a different format and system.
WINDOWS_TARGET: dict[str, Any] = {
    "target": {"os": "windows", "file": {"type": "application/x-dosexec", "size": 5}},
    "behavior": {},
}
ANDROID_TARGET: dict[str, Any] = {
    "target": {"file": {"type": "application/vnd.android.package-archive"}},
    "behavior": {},
}


def _marked_as(report: dict[str, Any]) -> dict[str, Any]:
    record = sandbox_target_record(INTAKE, OTHER)
    assert record is not None
    return {**copy.deepcopy(report), status.TARGET_KEY: status.target_mark(record)}


def _route(path: Any, report: dict[str, Any]) -> tuple[str, str]:
    from malspark.app import MalsparkApp

    return MalsparkApp(mock=True)._infer_sample_platform(path, report)


class TestTheRouting:
    """The router reads the sample alone where the report names another target."""

    @pytest.mark.parametrize(
        ("report", "unmarked"), [(WINDOWS_TARGET, "windows"), (ANDROID_TARGET, "android")]
    )
    def test_the_target_s_type_and_guest_never_route_the_sample(
        self, tmp_path: Path, report: dict[str, Any], unmarked: str
    ) -> None:
        path = _sample(tmp_path, b"plain words, no format of any kind\n")

        assert _route(path, copy.deepcopy(report))[1] == unmarked
        assert _route(path, _marked_as(report))[1] == "unknown"

    def test_the_sample_s_own_format_still_routes_it(self, tmp_path: Path) -> None:
        elf = b"\x7fELF\x02\x01\x01" + b"\x00" * 200

        assert _route(_sample(tmp_path, elf), _marked_as(WINDOWS_TARGET)) == ("elf", "linux")

    def test_the_reading_is_said(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="malspark"):
            _route(_sample(tmp_path), _marked_as(WINDOWS_TARGET))

        assert any("read from its own bytes only" in r.getMessage() for r in caplog.records)
