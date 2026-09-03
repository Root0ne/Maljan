import os
import stat
import sys
import time
from pathlib import Path

import pytest

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.worker import sample_files as sf  # noqa: E402


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
    (sf.work_dir() / "aaa.exe").write_bytes(b"x")
    (sf.temp_dir() / "aaa.exe").write_bytes(b"x")
    (sf.work_dir() / "bbb.exe").write_bytes(b"x")
    corpus = Path(sf.settings.samples_dir) / "aaa.exe"  # operator's own file, outside .work
    corpus.write_bytes(b"x")
    removed = sf.remove_for_sha("aaa")
    assert {p.name for p in removed} == {"aaa.exe"} and len(removed) == 2
    assert (sf.work_dir() / "bbb.exe").exists() and corpus.exists()


def test_sweep_removes_only_old_files_in_the_scoped_dirs(dirs):
    old = sf.work_dir() / "old.exe"
    old.write_bytes(b"x")
    os.utime(old, (time.time() - 90_000, time.time() - 90_000))
    fresh = sf.temp_dir() / "fresh.exe"
    fresh.write_bytes(b"x")
    corpus = Path(sf.settings.samples_dir) / "keep.exe"
    corpus.write_bytes(b"x")
    os.utime(corpus, (time.time() - 90_000, time.time() - 90_000))
    assert sf.sweep() == 1
    assert not old.exists() and fresh.exists() and corpus.exists()


def test_remove_quietly_never_raises(dirs):
    sf.remove_quietly(dirs / "missing.bin")
    sf.remove_quietly(None)
