"""The mirror runs when the provider needs one, and not otherwise."""

from __future__ import annotations

import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.worker.analysis_worker import mirror_target_for  # noqa: E402


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
