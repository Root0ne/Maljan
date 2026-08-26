"""BUG-02 regression: JobResponse surfaces the sample hash + filename.

The job API used to expose only the opaque ``sample_id`` UUID, so the live
analysis header showed a UUID until the rich report landed. ``JobResponse`` now
carries ``sample_sha256`` / ``sample_filename`` (populated from the eager-loaded
``sample`` relationship). These tests pin the schema contract without a DB.
"""

import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

# The API package lives under apps/api (its own import root).
_API_ROOT = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API_ROOT) not in sys.path:
    sys.path.insert(0, str(_API_ROOT))

from app.schemas.job import JobResponse  # noqa: E402


class _FakeJob:
    """Duck-typed stand-in for an eager-loaded AnalysisJob ORM row."""

    def __init__(self, sha: str | None, name: str | None) -> None:
        self.id = uuid.uuid4()
        self.sample_id = uuid.uuid4()
        self.sample_sha256 = sha
        self.sample_filename = name
        self.status = "completed"
        self.config = None
        self.created_at = datetime.now(UTC)
        self.started_at = None
        self.completed_at = None
        self.duration_seconds = None
        self.error_message = None


def test_job_response_surfaces_sample_hash_and_name() -> None:
    job = _FakeJob(sha="007257bf103de1173f536937eae72ea3f6f99c8e6", name="pony.exe")
    resp = JobResponse.model_validate(job)
    assert resp.sample_sha256 == "007257bf103de1173f536937eae72ea3f6f99c8e6"
    assert resp.sample_filename == "pony.exe"
    assert resp.sample_id == job.sample_id  # UUID still present


def test_job_response_sample_fields_default_to_none() -> None:
    job = _FakeJob(sha=None, name=None)
    resp = JobResponse.model_validate(job)
    assert resp.sample_sha256 is None
    assert resp.sample_filename is None
