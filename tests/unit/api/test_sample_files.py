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


def test_sweep_skips_a_file_that_vanishes_between_listing_and_unlink(dirs, monkeypatch):
    """One file that disappears (or becomes unreadable) mid-sweep must not
    abort the sweep for every other file in the scoped directories."""
    vanished = sf.work_dir() / f"{A}.exe"
    vanished.write_bytes(b"x")
    os.utime(vanished, (time.time() - 90_000, time.time() - 90_000))
    old = sf.temp_dir() / f"{B}.exe"
    old.write_bytes(b"x")
    os.utime(old, (time.time() - 90_000, time.time() - 90_000))

    real_unlink = os.unlink

    def flaky_unlink(path, *args, **kwargs):
        if str(path) == vanished.name:
            raise FileNotFoundError(path)
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(sf.os, "unlink", flaky_unlink)

    assert sf.sweep() == 1
    assert os.path.exists(vanished)
    assert not old.exists()


def test_an_orphaned_upload_staging_file_is_swept(dirs):
    """The API stages an upload as ``maljan-upload-*`` there; a crash leaves it behind."""
    staged = sf.temp_dir() / "maljan-upload-k2j3h4"
    staged.write_bytes(b"MZ live sample")
    other = sf.temp_dir() / "anything-else.bin"
    other.write_bytes(b"x")
    fresh = sf.temp_dir() / "maljan-upload-fresh"
    fresh.write_bytes(b"x")
    for path in (staged, other):
        os.utime(path, (time.time() - 90_000, time.time() - 90_000))
    assert sf.sweep() == 2
    assert not staged.exists() and not other.exists() and fresh.exists()


def test_a_link_in_the_upload_directory_is_not_followed(dirs):
    target = dirs / "precious.bin"
    target.write_bytes(b"keep")
    link = sf.temp_dir() / "maljan-upload-link"
    link.symlink_to(target)
    os.utime(link, (time.time() - 90_000, time.time() - 90_000), follow_symlinks=False)
    sf.sweep()
    assert target.read_bytes() == b"keep"


def test_a_copy_onto_a_planted_link_writes_nothing_outside(dirs):
    """A link planted where the copy goes is replaced by the copy, never written through."""
    outside = dirs / "bashrc"
    outside.write_bytes(b"original")
    os.chmod(outside, 0o644)
    dest = sf.work_dir() / f"{A}.exe"
    dest.symlink_to(outside)
    src = dirs / "src.bin"
    src.write_bytes(b"MZ sample")

    sf.private_copy(src, dest)

    assert outside.read_bytes() == b"original"
    assert stat.S_IMODE(os.stat(outside).st_mode) == 0o644
    assert not dest.is_symlink() and dest.read_bytes() == b"MZ sample"
    assert stat.S_IMODE(os.lstat(dest).st_mode) == 0o600


def test_a_copy_into_a_directory_swapped_for_a_link_writes_nothing_outside(dirs):
    outside = dirs / "elsewhere"
    outside.mkdir()
    made = sf.work_dir("swapped")
    made.joinpath(sf.MIRROR_MARKER).unlink()
    made.rmdir()
    made.symlink_to(outside, target_is_directory=True)
    src = dirs / "src.bin"
    src.write_bytes(b"MZ")
    with pytest.raises(OSError):
        sf.private_copy(src, made / f"{A}.exe")
    assert list(outside.iterdir()) == []


def test_a_stale_copy_is_replaced(dirs):
    dest = sf.work_dir() / f"{A}.exe"
    dest.write_bytes(b"old")
    src = dirs / "src.bin"
    src.write_bytes(b"new")
    sf.private_copy(src, dest)
    assert dest.read_bytes() == b"new"


@pytest.mark.parametrize(
    "plant",
    [
        lambda d: (d / sf.MIRROR_MARKER).write_text("copied in with a dataset\n"),
        lambda d: (d / sf.MIRROR_MARKER).mkdir(),
        lambda d: (d / sf.MIRROR_MARKER).symlink_to(d.parent / "real-marker"),
    ],
    ids=["other text", "a directory", "a link"],
)
def test_a_marker_that_is_not_the_worker_s_own_adopts_nothing(dirs, plant):
    samples = Path(sf.settings.samples_dir)
    folder = samples / "dataset"
    folder.mkdir(parents=True, mode=0o755)
    (samples / "real-marker").write_text(sf.MIRROR_MARKER_TEXT)
    (folder / f"{A}.exe").write_bytes(b"corpus")
    plant(folder)
    with pytest.raises(sf.NotAMirrorDirectory):
        sf.work_dir("dataset")
    assert sf.remove_for_sha(A, subdirs=["dataset"]) == []
    assert (folder / f"{A}.exe").read_bytes() == b"corpus"
    assert stat.S_IMODE(os.stat(folder).st_mode) == 0o755


def test_a_shipped_directory_with_a_foreign_marker_is_refused_too(dirs):
    shipped = Path(sf.settings.samples_dir) / ".work"
    shipped.mkdir(parents=True, mode=0o755)
    (shipped / sf.MIRROR_MARKER).write_text("not ours\n")
    with pytest.raises(sf.NotAMirrorDirectory):
        sf.work_dir(".work")


def test_the_worker_s_own_marker_adopts_the_directory(dirs):
    folder = Path(sf.settings.samples_dir) / "mine"
    folder.mkdir(parents=True, mode=0o755)
    (folder / sf.MIRROR_MARKER).write_text(sf.MIRROR_MARKER_TEXT)
    assert sf.work_dir("mine") == folder.resolve()
    assert stat.S_IMODE(os.stat(folder).st_mode) == 0o700


def test_a_directory_that_cannot_be_opened_skips_only_itself(dirs, monkeypatch):
    stale = sf.work_dir("r2-work") / f"{C}.exe"
    stale.write_bytes(b"x")
    os.utime(stale, (time.time() - 90_000, time.time() - 90_000))
    real_open_mirror = sf._open_mirror

    def refusing(name):
        if name == ".work":
            raise PermissionError(name)
        return real_open_mirror(name)

    monkeypatch.setattr(sf, "_open_mirror", refusing)
    assert sf.sweep() == 1
    assert not stale.exists()
    assert sf.remove_for_sha(D) == []


def test_a_directory_that_cannot_be_listed_skips_only_itself(dirs, monkeypatch):
    stale = sf.work_dir("r2-work") / f"{C}.exe"
    stale.write_bytes(b"x")
    os.utime(stale, (time.time() - 90_000, time.time() - 90_000))
    real_scandir = os.scandir
    upload_fd: list[int] = []
    real_open = os.open

    def recording_open(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if Path(str(path)) == sf.temp_dir():
            upload_fd.append(fd)
        return fd

    def refusing(target):
        if upload_fd and target == upload_fd[-1]:
            raise PermissionError("upload directory")
        return real_scandir(target)

    monkeypatch.setattr(sf.os, "open", recording_open)
    monkeypatch.setattr(sf.os, "scandir", refusing)
    assert sf.sweep() == 1
    assert not stale.exists()
