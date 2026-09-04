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
