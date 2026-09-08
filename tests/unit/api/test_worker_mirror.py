"""The mirror runs when the provider needs one, and not otherwise."""

from __future__ import annotations

from app.worker.analysis_worker import mirror_target_for


class _Caps:
    def __init__(self, needed):
        self.needs_sample_mirror = needed


class _Provider:
    def __init__(self, needed, spec):
        self.capabilities = _Caps(needed)
        self._spec = spec

    def mirror_spec(self):
        return self._spec


def test_no_mirror_when_the_provider_does_not_need_one():
    assert mirror_target_for(_Provider(False, None), sha256="a" * 64, extension=".exe") is None


def test_the_mirror_path_comes_from_the_provider_spec():
    from maljan.providers.base import MirrorSpec

    spec = MirrorSpec(work_subdir=".work", container_prefix="/data/samples")
    host, container = mirror_target_for(_Provider(True, spec), sha256="b" * 64, extension=".exe")
    assert host.name == f"{'b' * 64}.exe"
    assert host.parent.name == ".work"
    assert container == f"/data/samples/.work/{'b' * 64}.exe"


def test_a_ghidra_spec_still_yields_the_container_path():
    """Regression: the empty-prefix branch below must not touch this path."""
    from maljan.providers.base import MirrorSpec

    spec = MirrorSpec(work_subdir=".work", container_prefix="/data/samples")
    host, container = mirror_target_for(_Provider(True, spec), sha256="d" * 64, extension=".exe")
    assert container == f"/data/samples/.work/{'d' * 64}.exe"


def test_an_empty_container_prefix_yields_the_host_path_itself():
    """A co-located server (radare2's stdio r2mcp) has no separate container
    mount: the analyst-facing path is the same path the worker mirrored to."""
    from maljan.providers.base import MirrorSpec

    spec = MirrorSpec(work_subdir=".work", container_prefix="")
    host, analyst_path = mirror_target_for(_Provider(True, spec), sha256="c" * 64, extension=".exe")
    assert analyst_path == str(host)


def test_the_r2_provider_gets_its_own_host_path_as_the_analyst_path():
    from maljan.core.config import Settings
    from maljan.providers.static.r2 import R2StaticProvider

    cfg = Settings(_env_file=None)
    cfg.static.provider = "r2"
    cfg.static.r2.enabled = True
    provider = R2StaticProvider.from_settings(cfg)

    host, analyst_path = mirror_target_for(provider, sha256="e" * 64, extension=".exe")
    assert analyst_path == str(host)


# ---------------------------------------------------------------------------
# BUG 10: the host directory came from ``sample_files.work_dir()`` regardless
# of what the provider's spec asked for, so r2 — whose spec names its own
# subdirectory — was mirrored into the hidden ``.work`` that radare2 refuses to
# open. The spec's ``work_subdir`` now decides the host directory too, which is
# what made it a field in the first place.
# ---------------------------------------------------------------------------


def test_the_host_directory_follows_the_specs_subdirectory(tmp_path, monkeypatch):
    from app.worker import sample_files
    from maljan.providers.base import MirrorSpec

    monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path))

    ghidra = MirrorSpec(work_subdir=".work", container_prefix="/data/samples")
    r2 = MirrorSpec(work_subdir="r2-work", container_prefix="")

    ghidra_host, _ = mirror_target_for(_Provider(True, ghidra), sha256="a" * 64, extension=".exe")
    r2_host, _ = mirror_target_for(_Provider(True, r2), sha256="a" * 64, extension=".exe")

    assert ghidra_host.parent.name == ".work"
    assert r2_host.parent.name == "r2-work"
    assert ghidra_host != r2_host


def test_the_r2_mirror_path_has_no_hidden_segment(tmp_path, monkeypatch):
    """The property the live failure came down to: r2mcp refuses a path with a
    ``/.`` segment, so no part of the mirror path may be hidden."""
    from app.worker import sample_files
    from maljan.core.config import Settings
    from maljan.providers.static.r2 import R2StaticProvider

    monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path))

    cfg = Settings(_env_file=None)
    cfg.static.provider = "r2"
    cfg.static.r2.enabled = True
    host, analyst_path = mirror_target_for(
        R2StaticProvider.from_settings(cfg), sha256="f" * 64, extension=".exe"
    )

    hidden = [p for p in host.parts if p.startswith(".") and p not in (".", "..")]
    assert hidden == [], f"radare2 cannot open this path: {host} (hidden segments {hidden})"
    assert analyst_path == str(host)


def test_the_r2_mirror_directory_is_created_private(tmp_path, monkeypatch):
    """Same 0o700 as ``.work``: it holds uploaded sample bytes either way."""
    import os

    from app.worker import sample_files

    monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path))

    created = sample_files.work_dir("r2-work")
    assert created.is_dir()
    assert oct(os.stat(created).st_mode & 0o777) == "0o700"


def test_cleanup_reaches_every_mirror_directory(tmp_path, monkeypatch):
    """``remove_for_sha`` swept only ``.work``; a copy in the r2 directory
    would have outlived its job."""
    from app.worker import sample_files

    monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path))
    monkeypatch.setattr(sample_files.settings, "upload_temp_dir", str(tmp_path / "tmp"))

    sha = "c" * 64
    ghidra_copy = sample_files.work_dir() / f"{sha}.exe"
    r2_copy = sample_files.work_dir("r2-work") / f"{sha}.exe"
    for path in (ghidra_copy, r2_copy):
        path.write_bytes(b"MZ")

    removed = sample_files.remove_for_sha(sha)

    assert set(removed) == {ghidra_copy, r2_copy}
    assert not ghidra_copy.exists()
    assert not r2_copy.exists()


def test_the_sweep_reaches_every_mirror_directory(tmp_path, monkeypatch):
    import os
    import time

    from app.worker import sample_files

    monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path))
    monkeypatch.setattr(sample_files.settings, "upload_temp_dir", str(tmp_path / "tmp"))

    stale = sample_files.work_dir("r2-work") / f"{'d' * 64}.exe"
    stale.write_bytes(b"MZ")
    old = time.time() - 100_000
    os.utime(stale, (old, old))

    assert sample_files.sweep(max_age_s=86_400.0) == 1
    assert not stale.exists()


def test_two_providers_landing_on_one_host_path_still_copy_once(tmp_path, monkeypatch):
    """The dedup that `test_each_distinct_host_path_is_copied_once_and_cleaned_up`
    used to cover with Ghidra and r2, before BUG 10 gave those two separate
    directories. Any pair that shares a mirror subdirectory still copies once."""
    from app.worker import analysis_worker, sample_files
    from maljan.providers.base import MirrorSpec

    monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path))
    monkeypatch.setattr(analysis_worker, "profile_static_providers", lambda _c: ["one", "two"])

    spec = MirrorSpec(work_subdir=".work", container_prefix="/data/samples")

    class _Container:
        def get_static_provider(self, _id):
            return _Provider(True, spec)

    calls = []
    host_mirrors, paths = analysis_worker.mirror_static_samples(
        _Container(),
        temp_path=str(tmp_path / "src.exe"),
        sha256="e" * 64,
        extension=".exe",
        copy_fn=lambda src, dst: calls.append(dst),
    )

    assert len(calls) == 1
    assert len(host_mirrors) == 1
    assert set(paths) == {"one", "two"}


# ---------------------------------------------------------------------------
# Wave-4 review F1: `Path(subdir).name` keeps "..", so a configured mirror_dir
# ending in `..` resolved *outside* samples_dir — which `_private_dir` then
# chmods 0o700 and `sweep()` deletes stale files in. "" and "." were quieter
# but no better: `.name` is empty, the old code fell back to the hidden
# `.work`, and r2 was silently re-broken by the very setting that exists to
# stop that.
# ---------------------------------------------------------------------------


def test_a_traversal_subdirectory_is_refused(tmp_path, monkeypatch):
    import pytest

    from app.worker import sample_files

    monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path / "samples"))

    for bad in ("..", "data/samples/..", "", "."):
        with pytest.raises(ValueError, match="mirror directory"):
            sample_files.work_dir(bad)

    assert not (tmp_path / "samples").exists(), "a refused name must create nothing"


def test_an_empty_name_does_not_fall_back_to_the_hidden_default(tmp_path, monkeypatch):
    """The silent half of the finding: falling back to `.work` would put r2's
    sample back where radare2 refuses to open it."""
    import pytest

    from app.worker import sample_files

    monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path))
    with pytest.raises(ValueError):
        sample_files.work_dir("")


def test_an_ordinary_subdirectory_is_still_accepted(tmp_path, monkeypatch):
    from app.worker import sample_files

    monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path))
    assert sample_files.work_dir("r2-work").parent == tmp_path.resolve()
