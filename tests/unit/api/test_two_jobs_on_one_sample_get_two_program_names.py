"""A mirror copy is named by the job too, so a server naming programs by file holds one per job."""

from __future__ import annotations

from app.worker import sample_files
from app.worker.analysis_worker import mirror_target_for

JOB_A = "11111111-1111-4111-8111-111111111111"
JOB_B = "22222222-2222-4222-8222-222222222222"


class _Provider:
    def __init__(self, spec):
        self.capabilities = type("Caps", (), {"needs_sample_mirror": True})()
        self._spec = spec

    def mirror_spec(self):
        return self._spec


def _spec():
    from maljan.providers.base import MirrorSpec

    return MirrorSpec(work_subdir=".work", container_prefix="/data/samples")


def test_two_jobs_on_one_sha256_get_two_names() -> None:
    sha = "a" * 64
    a_host, a_path = mirror_target_for(
        _Provider(_spec()), sha256=sha, extension=".exe", job_id=JOB_A
    )
    b_host, b_path = mirror_target_for(
        _Provider(_spec()), sha256=sha, extension=".exe", job_id=JOB_B
    )

    assert a_host != b_host and a_path != b_path
    assert a_host.name == f"{sha}.{JOB_A}.exe"
    assert a_path == f"/data/samples/.work/{sha}.{JOB_A}.exe"


def test_a_job_scoped_copy_is_still_a_sample_copy_with_its_digest_and_suffix() -> None:
    sha = "b" * 64
    name = sample_files.copy_name(sha, ".dll", JOB_A)

    assert sample_files._is_sample_copy(name)
    assert sample_files._is_sample_copy(name, sha)
    assert name.split(".", 1)[0] == sha and name.endswith(".dll")


def test_no_job_keeps_the_plain_name() -> None:
    assert sample_files.copy_name("c" * 64, ".exe") == f"{'c' * 64}.exe"
    assert sample_files.copy_name("c" * 64, ".exe", "../x") == f"{'c' * 64}.exe"
