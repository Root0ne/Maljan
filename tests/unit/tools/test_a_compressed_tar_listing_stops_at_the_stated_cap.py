"""A compressed tar is listed header by header and the listing stops, said, at the platform's cap.

A tar's headers stand between its members' data in one compressed stream, so
listing a ``.tar.bz2`` inflates every member before the last header: 6.6 KB
of bzip2 stood for 1 GiB of zeros, all of it inflated by ``getmembers``. The
headers are now read one at a time and the read stops before the stream would
pass the larger of the file's size and the platform's sample upload cap, the
cap every decompression a tool does stops at; the answer says so. Below the
cap the listing is the one ``getmembers`` gave (inlined below). The work is
counted (bytes inflated), never timed.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import random
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from maljan.core.delivery_limits import SAMPLE_UPLOAD_MAX_BYTES
from maljan.tools import binary


def _old_tar_members(target: Path, limit: int) -> dict[str, Any]:
    with tarfile.open(target) as archive:
        infos = archive.getmembers()
        members = [
            {"name": info.name, "size": int(info.size), "is_dir": info.isdir()}
            for info in infos[:limit]
        ]
    return {
        "format": "tar",
        "members": members,
        "total": len(infos),
        "truncated": len(infos) > limit,
    }


def _tar(rng: random.Random, members: int) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        for index in range(members):
            info = tarfile.TarInfo(f"dir/member{index}")
            if rng.random() < 0.1:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
                continue
            payload = rng.randbytes(rng.randrange(0, 3000))
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    return out.getvalue()


_WRAPS: dict[str, Callable[[bytes], bytes]] = {
    "plain": bytes,
    "gz": gzip.compress,
    "bz2": bz2.compress,
    "xz": lzma.compress,
}


def test_the_cap_is_the_platform_s_sample_upload_cap() -> None:
    assert binary.ARCHIVE_STREAM_CAP == SAMPLE_UPLOAD_MAX_BYTES


@pytest.mark.parametrize("wrap", sorted(_WRAPS))
@pytest.mark.parametrize("seed", range(4))
def test_below_the_cap_the_listing_is_the_one_it_was(tmp_path: Path, wrap: str, seed: int) -> None:
    rng = random.Random(seed)
    path = tmp_path / "archive"
    path.write_bytes(_WRAPS[wrap](_tar(rng, rng.randrange(0, 30))))
    for limit in (0, 3, 500):
        assert binary._tar_members(path, limit) == _old_tar_members(path, limit)


def _old_listing(path: Path) -> object:
    """``archive_list``'s tar step as it was: ``is_tarfile``, then ``getmembers``."""
    if not tarfile.is_tarfile(path):
        return None
    return _old_tar_members(path, 500)


def _outcome(read: Callable[[], object]) -> object:
    try:
        return read()
    except Exception as exc:  # noqa: BLE001
        return type(exc)


@pytest.mark.parametrize("wrap", sorted(_WRAPS))
@pytest.mark.parametrize("cut", [0.1, 0.3, 0.5, 0.8, 0.97])
def test_a_truncated_tar_reads_or_fails_as_it_did(tmp_path: Path, wrap: str, cut: float) -> None:
    whole = _WRAPS[wrap](_tar(random.Random(1), 40))
    path = tmp_path / "archive"
    path.write_bytes(whole[: max(1, int(len(whole) * cut))])
    assert _outcome(lambda: binary._tar_members(path, 500)) == _outcome(lambda: _old_listing(path))


_DECOMPRESSOR = bz2.BZ2Decompressor


class _Counted:
    """A bzip2 decompressor that counts the bytes it hands out."""

    inflated = 0

    def __init__(self) -> None:
        self._inner = _DECOMPRESSOR()

    def decompress(self, data: bytes, max_length: int = -1) -> bytes:
        out = self._inner.decompress(data, max_length)
        _Counted.inflated += len(out)
        return out

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def test_a_bomb_is_listed_up_to_the_cap_and_the_stop_is_said(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = io.BytesIO()
    member = 1 << 20
    with tarfile.open(fileobj=out, mode="w:bz2") as archive:
        for index in range(8):
            info = tarfile.TarInfo(f"zeros{index}")
            info.size = member
            archive.addfile(info, io.BytesIO(bytes(member)))
    path = tmp_path / "bomb.tar.bz2"
    path.write_bytes(out.getvalue())
    cap = 3 * member
    assert path.stat().st_size < cap
    monkeypatch.setattr(binary, "ARCHIVE_STREAM_CAP", cap)
    monkeypatch.setattr(bz2, "BZ2Decompressor", _Counted)
    _Counted.inflated = 0

    answer = binary.archive_list(str(path))

    assert answer["total"] == 3
    assert [m["name"] for m in answer["members"]] == ["zeros0", "zeros1", "zeros2"]
    assert answer["truncated"] is True
    assert "stopped after 3 members" in answer["listing_stopped"]
    assert str(cap) in answer["listing_stopped"]
    # Nothing past the cap was inflated (the reads run a buffer ahead).
    assert _Counted.inflated <= cap + member


@pytest.mark.parametrize("form", [tarfile.GNU_FORMAT, tarfile.PAX_FORMAT])
def test_an_oversized_long_name_header_is_held_to_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, form: int
) -> None:
    """A GNU long name or a pax header is read through the same counter as member data."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:bz2", format=form) as archive:
        info = tarfile.TarInfo("n" * (4 << 20))
        archive.addfile(info, io.BytesIO(b""))
    path = tmp_path / "names.tar.bz2"
    path.write_bytes(out.getvalue())
    cap = 1 << 20
    assert path.stat().st_size < cap
    monkeypatch.setattr(binary, "ARCHIVE_STREAM_CAP", cap)
    monkeypatch.setattr(bz2, "BZ2Decompressor", _Counted)
    _Counted.inflated = 0

    answer = binary.archive_list(str(path))

    assert answer["total"] == 0
    assert answer["members"] == []
    assert "stopped after 0 members" in answer["listing_stopped"]
    # The reader takes at most one byte past the cap; the decompressor runs a
    # buffer ahead of it.
    assert _Counted.inflated <= cap + (1 << 20)


def _polyglot() -> bytes:
    """A file that is both a plain tar (one member named ``AAAA...``) and a gzip stream of a
    tar holding ``payload.exe``: the gzip header doubles as the plain tar's first header."""
    import struct
    import zlib

    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo("payload.exe")
        payload = b"MZ" + bytes(100)
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    raw = inner.getvalue()
    header = bytearray(b"A" * 512)
    # gzip magic, deflate, FCOMMENT; the comment runs to the NUL after this block.
    header[0:10] = b"\x1f\x8b\x08\x10\x01\x01\x01\x01\x00\x03"
    header[10:100] = b"B" * 90
    header[100:108] = b"0000644 "
    header[108:116] = b"0000000 "
    header[116:124] = b"0000000 "
    header[124:136] = b"00000000000 "
    header[136:148] = b"00000000000 "
    header[156:157] = b"0"
    header[157:257] = b"C" * 100
    header[329:345] = b" " * 16
    header[148:156] = b"        "
    header[148:156] = b"%07o " % sum(header)
    stream = zlib.compressobj(9, zlib.DEFLATED, -15)
    body = stream.compress(raw) + stream.flush()
    trailer = struct.pack("<II", zlib.crc32(raw) & 0xFFFFFFFF, len(raw))
    return bytes(header) + b"\x00" + body + trailer


def test_a_tar_gzip_polyglot_is_listed_as_tarfile_open_reads_it(tmp_path: Path) -> None:
    path = tmp_path / "polyglot.tar"
    path.write_bytes(_polyglot())
    assert [m.name for m in tarfile.open(path, "r:").getmembers()][0].startswith("AAAA")
    expected = [m.name for m in tarfile.open(path).getmembers()]
    assert expected == ["payload.exe"]
    answer = binary.archive_list(str(path))
    assert [m["name"] for m in answer["members"]] == expected
    assert answer == _old_listing(path)


@pytest.mark.parametrize("wrap", ["gz", "bz2", "xz"])
def test_a_stream_cut_inside_its_first_header_fails_or_moves_on_as_it_did(
    tmp_path: Path, wrap: str
) -> None:
    """gzip lets an early end of stream through, bzip2 and xz turn it into "not this kind"."""
    whole = _WRAPS[wrap](_tar(random.Random(3), 3))
    path = tmp_path / "archive"
    for cut in range(1, min(len(whole), 400), 3):
        path.write_bytes(whole[:cut])
        expected = _outcome(lambda: _old_listing(path))
        assert _outcome(lambda: binary._tar_members(path, 500)) == expected, cut
