import os
import stat
import time
from pathlib import Path

import pytest

from app.worker import sample_files as sf

A = "a" * 64
B = "b" * 64
C = "c" * 64
D = "d" * 64


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(sf.settings, "upload_temp_dir", str(tmp_path / "tmp"))
    monkeypatch.setattr(sf.settings, "samples_dir", str(tmp_path / "samples"))
    return tmp_path


def test_directories_and_files_are_private(dirs):
    src = dirs / "src.bin"
    src.write_bytes(b"MZ" * 10)
    dest = sf.work_dir() / "abc.exe"
    sf.private_copy(src, dest)
    assert stat.S_IMODE(os.stat(sf.work_dir()).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(sf.temp_dir()).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(dest).st_mode) == 0o600
    assert dest.read_bytes() == b"MZ" * 10
    assert sf.work_dir().name == ".work" and sf.work_dir().parent == (dirs / "samples").resolve()


def test_remove_for_sha_touches_only_that_hash_and_only_the_scoped_dirs(dirs):
    (sf.work_dir() / f"{A}.exe").write_bytes(b"x")
    (sf.temp_dir() / f"{A}.exe").write_bytes(b"x")
    (sf.work_dir() / f"{B}.exe").write_bytes(b"x")
    # Named after the sample, but not as the worker names a copy.
    (sf.work_dir() / f"{A}.exe notes").write_bytes(b"x")
    corpus = Path(sf.settings.samples_dir) / f"{A}.exe"  # operator's own file, outside .work
    corpus.write_bytes(b"x")
    removed = sf.remove_for_sha(A)
    assert {p.name for p in removed} == {f"{A}.exe"} and len(removed) == 2
    assert (sf.work_dir() / f"{B}.exe").exists() and corpus.exists()
    assert (sf.work_dir() / f"{A}.exe notes").exists()


def test_a_prefix_of_a_hash_or_a_pattern_removes_nothing(dirs):
    (sf.work_dir() / f"{A}.exe").write_bytes(b"x")
    assert sf.remove_for_sha("aaa") == []
    assert sf.remove_for_sha("*") == []
    assert (sf.work_dir() / f"{A}.exe").exists()


def test_sweep_removes_only_old_files_in_the_scoped_dirs(dirs):
    old = sf.work_dir() / f"{C}.exe"
    old.write_bytes(b"x")
    os.utime(old, (time.time() - 90_000, time.time() - 90_000))
    not_a_copy = sf.work_dir() / "notes.txt"
    not_a_copy.write_bytes(b"x")
    os.utime(not_a_copy, (time.time() - 90_000, time.time() - 90_000))
    fresh = sf.temp_dir() / f"{D}.exe"
    fresh.write_bytes(b"x")
    corpus = Path(sf.settings.samples_dir) / f"{C}.exe"
    corpus.write_bytes(b"x")
    os.utime(corpus, (time.time() - 90_000, time.time() - 90_000))
    assert sf.sweep() == 1
    assert not old.exists() and fresh.exists() and corpus.exists() and not_a_copy.exists()


def test_remove_quietly_never_raises(dirs):
    sf.remove_quietly(dirs / "missing.bin")
    sf.remove_quietly(None)


def test_sweep_skips_a_file_that_vanishes_between_iterdir_and_stat(dirs, monkeypatch):
    """One file that disappears (or becomes unreadable) mid-sweep must not
    abort the sweep for every other file in the scoped directories."""
    vanished = sf.work_dir() / f"{A}.exe"
    vanished.write_bytes(b"x")
    os.utime(vanished, (time.time() - 90_000, time.time() - 90_000))
    old = sf.temp_dir() / f"{B}.exe"
    old.write_bytes(b"x")
    os.utime(old, (time.time() - 90_000, time.time() - 90_000))

    real_lstat = os.lstat

    def flaky_lstat(path, *args, **kwargs):
        if Path(path) == vanished:
            raise FileNotFoundError(path)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(sf.os, "lstat", flaky_lstat)

    assert sf.sweep() == 1
    assert os.path.exists(vanished)  # never got past the raising lstat() call
    assert not old.exists()
