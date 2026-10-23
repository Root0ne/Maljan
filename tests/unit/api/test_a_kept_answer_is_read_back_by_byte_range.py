"""The job's store hands a kept part back by byte range (what ``read_evidence`` pages through).

``JobEvidenceSpill.read`` waits for the job's own background write of the bytes,
then reads the object through the job's client from an offset. Bytes the job
never handed over, a failed write and a store that cannot be read give ``None``.
"""

from __future__ import annotations

import hashlib
from typing import Any

from app.services import object_store
from maljan.schemas.evidence_spill import ANSWER, spill_part

BLOB = ("0123456789" * 30).encode()


class _Response:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data

    def close(self) -> None:
        return None

    def release_conn(self) -> None:
        return None


class _Store:
    def __init__(self, *, refuses_reads: bool = False, refuses_writes: bool = False) -> None:
        self.objects: dict[str, bytes] = {}
        self.refuses_reads = refuses_reads
        self.refuses_writes = refuses_writes
        self.reads: list[tuple[str, int, int]] = []

    def bucket_exists(self, bucket: str) -> bool:
        return True

    def put_object(self, bucket: str, path: str, data: Any, length: int, content_type: str) -> None:
        if self.refuses_writes:
            raise ValueError("refused")
        self.objects[path] = data.read()

    def get_object(self, bucket: str, path: str, offset: int = 0, length: int = 0) -> _Response:
        if self.refuses_reads:
            raise OSError("down")
        self.reads.append((path, offset, length))
        blob = self.objects[path]
        return _Response(blob[offset : offset + length] if length else blob[offset:])


def _kept(store: _Store) -> tuple[Any, str]:
    sink = object_store.evidence_spill("job", store=store)
    ref = spill_part(sink, ANSWER, BLOB.decode())
    assert ref["sha256"] == hashlib.sha256(BLOB).hexdigest()
    return sink, ref["sha256"]


class TestReadingAKeptPart:
    def test_a_range_is_read_once_the_write_has_ended(self) -> None:
        store = _Store()
        sink, digest = _kept(store)
        assert sink.read(digest, 5, 10) == BLOB[5:15]
        assert store.reads[-1][1:] == (5, 10)

    def test_no_length_reads_to_the_end(self) -> None:
        sink, digest = _kept(_Store())
        assert sink.read(digest, 290) == BLOB[290:]

    def test_bytes_the_job_never_wrote_are_not_there(self) -> None:
        sink, _digest = _kept(_Store())
        assert sink.read("f" * 64, 0, 5) is None

    def test_a_failed_write_is_not_there(self) -> None:
        sink, digest = _kept(_Store(refuses_writes=True))
        assert sink.read(digest, 0, 5) is None

    def test_a_store_that_cannot_be_read_gives_none(self) -> None:
        sink, digest = _kept(_Store(refuses_reads=True))
        assert sink.read(digest, 0, 5) is None
