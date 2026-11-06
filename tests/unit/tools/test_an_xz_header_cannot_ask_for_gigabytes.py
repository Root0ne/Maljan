"""A compressed stream's header cannot make the archive lister allocate gigabytes.

The legacy .lzma header names its dictionary size, up to 4 GiB, and the
decoder allocates it before it reads a byte. The fuzzer found a 202-byte
input that made ``archive_list`` ask for 4 GiB. The xz and lzma decoder is
given ``LZMA_MEMORY_LIMIT``: such a header is a decoding error, the file is
tried as the next format, and a real ``.tar.xz`` still lists.
"""

from __future__ import annotations

import io
import resource
import tarfile
from pathlib import Path

import pytest

from maljan.tools import binary

LEGACY_LZMA_4_GIB = (
    bytes([0x5D]) + (0xFFFFFFFF).to_bytes(4, "little") + (0).to_bytes(8, "little") + b"\x00" * 64
)
FUZZER_INPUT = b"\nI" + b"\xff" * 200


@pytest.fixture
def capped_memory():
    """At most 1 GiB of address space beyond what the process holds, so a 4 GiB ask fails."""
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    with open("/proc/self/statm") as statm:
        held = int(statm.read().split()[0]) * resource.getpagesize()
    cap = held + 1024 * 1024 * 1024
    if hard != resource.RLIM_INFINITY and hard < cap:
        cap = hard
    resource.setrlimit(resource.RLIMIT_AS, (cap, hard))
    try:
        yield
    finally:
        resource.setrlimit(resource.RLIMIT_AS, (soft, hard))


@pytest.mark.parametrize("blob", [LEGACY_LZMA_4_GIB, FUZZER_INPUT], ids=["lzma-4gib", "fuzzer"])
def test_a_header_asking_for_gigabytes_is_no_archive(
    tmp_path: Path, blob: bytes, capped_memory: None
) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(blob)
    answer = binary.archive_list(str(sample), limit=64)
    assert answer["error"] == "unsupported archive format"


def test_a_real_tar_xz_still_lists(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:xz", preset=9) as archive:
        info = tarfile.TarInfo("inner.txt")
        payload = b"hello"
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    sample = tmp_path / "sample.tar.xz"
    sample.write_bytes(buffer.getvalue())
    answer = binary.archive_list(str(sample), limit=64)
    assert answer["total"] == 1
    assert [member["name"] for member in answer["members"]] == ["inner.txt"]


def test_the_limit_fits_the_strongest_xz_preset() -> None:
    assert binary.LZMA_MEMORY_LIMIT >= 128 * 1024 * 1024
