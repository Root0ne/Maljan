"""A sample copy two jobs share is removed with the last of them, never under the other.

Every copy the worker writes is named by the sample's SHA-256, so two jobs on
one sample (two workers sharing the directories) reach the same name, and the
first job's cleanup used to delete the copy the second was still reading. Each
job now holds the copy it uses, and the copy goes with the last hold (AUD-36).
"""

from __future__ import annotations

import os
import time
import uuid
from pathlib import Path

import pytest

from app.worker import sample_files

SHA = "ab" * 32


def _job() -> str:
    return str(uuid.uuid4())


def _writer(dest: Path, calls: list[str]):
    def make(target: Path) -> None:
        calls.append("made")
        target.write_bytes(b"MZ sample")

    return make


def test_the_first_job_ending_leaves_the_copy_the_second_still_holds(tmp_path: Path) -> None:
    dest = tmp_path / f"{SHA}.exe"
    first, second = _job(), _job()
    calls: list[str] = []

    sample_files.hold_copy(dest, first, _writer(dest, calls))
    sample_files.hold_copy(dest, second, _writer(dest, calls))

    assert calls == ["made"], "a copy another job holds is not written again"
    assert sample_files.release_copy(dest, job_id=first) is False
    assert dest.read_bytes() == b"MZ sample"
    assert sample_files.release_copy(dest, job_id=second) is True
    assert not dest.exists()
    assert list(tmp_path.iterdir()) == []


def test_a_single_job_removes_its_copy_as_before(tmp_path: Path) -> None:
    dest = tmp_path / f"{SHA}.exe"
    job = _job()
    sample_files.held_copy(_source(tmp_path), dest, job_id=job)

    assert dest.exists()
    assert sample_files.release_copy(dest, job_id=job) is True
    assert list(tmp_path.iterdir()) == [tmp_path / "src"]


def test_a_stale_copy_nobody_holds_is_written_fresh(tmp_path: Path) -> None:
    dest = tmp_path / f"{SHA}.exe"
    dest.write_bytes(b"left over")
    calls: list[str] = []

    sample_files.hold_copy(dest, _job(), _writer(dest, calls))

    assert calls == ["made"]
    assert dest.read_bytes() == b"MZ sample"


def test_a_shared_copy_is_renewed_for_the_age_sweep(tmp_path: Path) -> None:
    dest = tmp_path / f"{SHA}.exe"
    sample_files.hold_copy(dest, _job(), _writer(dest, []))
    old = time.time() - 3 * 86_400
    os.utime(dest, (old, old))

    sample_files.hold_copy(dest, _job(), _writer(dest, []))

    assert dest.stat().st_mtime > old + 86_400


def test_a_copy_that_fails_leaves_no_hold(tmp_path: Path) -> None:
    dest = tmp_path / f"{SHA}.exe"

    def broken(target: Path) -> None:
        target.write_bytes(b"MZ")
        raise OSError("disk full")

    with pytest.raises(OSError):
        sample_files.hold_copy(dest, _job(), broken)

    assert list(tmp_path.iterdir()) == []


def test_a_hold_reads_as_a_copy_so_the_sweep_and_a_delete_take_it(tmp_path: Path) -> None:
    """A crashed job's hold goes with the copies, never outliving the sample."""
    dest = tmp_path / f"{SHA}.exe"
    job = _job()
    sample_files.hold_copy(dest, job, _writer(dest, []))
    holds = [p.name for p in tmp_path.iterdir() if p.name != dest.name]

    assert len(holds) == 1
    assert sample_files._is_sample_copy(holds[0], SHA)


def test_a_job_without_a_usable_id_copies_and_removes_unheld(tmp_path: Path) -> None:
    dest = tmp_path / f"{SHA}.exe"
    calls: list[str] = []

    sample_files.hold_copy(dest, "", _writer(dest, calls))
    assert calls == ["made"]
    assert list(tmp_path.iterdir()) == [dest]
    assert sample_files.release_copy(dest, job_id="") is True
    assert not dest.exists()


def test_releasing_nothing_is_a_no_op() -> None:
    assert sample_files.release_copy(None, job_id=_job()) is False


def _source(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    src.write_bytes(b"MZ sample")
    return src


def test_the_copy_is_written_aside_and_appears_whole(tmp_path: Path) -> None:
    """A reader of the copy's name never sees it half written."""
    dest = tmp_path / f"{SHA}.exe"
    seen: list[bool] = []

    def make(target: Path) -> None:
        assert target != dest
        target.write_bytes(b"MZ")
        seen.append(dest.exists())
        with target.open("ab") as out:
            out.write(b" sample")

    sample_files.hold_copy(dest, _job(), make)

    assert seen == [False]
    assert dest.read_bytes() == b"MZ sample"
    assert sample_files._is_sample_copy(f"{dest.name}.part-{_job()}", SHA)
