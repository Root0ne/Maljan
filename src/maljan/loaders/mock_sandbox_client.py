"""MockSandboxClient — fixture-based sandbox backend for tests and offline use.

Phase 6: CAPEv2 Sandbox Integration

Returns pre-built JSON fixture files instead of submitting to a real sandbox.
This enables:
  - Unit and integration tests with no network access.
  - Local development without a CAPEv2 instance.
  - Deterministic CI runs with known-good fixture data.

MockSandboxClient loads fixtures from a configurable directory. The fixture
file must be named <sample_sha256>.json or <sample_name>.json and must
conform to the CAPEv2 report JSON schema (same structure as existing
data/samples/ fixture files).

If no fixture file is found, a minimal synthetic report is returned so
downstream parsers always receive a valid (though nearly empty) payload.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from maljan.core.logger import logger
from maljan.loaders.sandbox_client import SandboxError, SubmissionResult


class MockSandboxClient:
    """Fixture-backed SandboxClient for tests and local development.

    Usage:
        client = MockSandboxClient(fixtures_dir="data/samples")
        task_id = client.submit("path/to/sample.exe")
        status = client.wait_for_completion(task_id)
        result = client.fetch_report(task_id)
    """

    def __init__(
        self,
        fixtures_dir: str | Path = "data/samples",
        default_dynamic_fixture: str | None = None,
    ) -> None:
        """Create a MockSandboxClient.

        Args:
            fixtures_dir:            Root directory containing fixture JSON files.
                                     Dynamic fixtures are looked up under
                                     <fixtures_dir>/dynamic/<task_id>.json.
            default_dynamic_fixture: Path to a fallback fixture JSON file to
                                     return when no task-specific file is found.
                                     When None, a minimal synthetic report is used.
        """
        self._fixtures_dir = Path(fixtures_dir)
        self._default_fixture = (
            Path(default_dynamic_fixture) if default_dynamic_fixture else None
        )
        # task_id -> sample metadata
        self._tasks: dict[str, dict[str, str]] = {}
        self._next_task_id = 1

    def submit(self, sample_path: str | Path) -> str:
        """Register a sample and return a synthetic task ID.

        No network call is made. The sample file is read only to compute its
        SHA-256 for fixture file lookup.
        """
        path = Path(sample_path)
        sha256 = self._sha256(path) if path.exists() else "mock_sha256"
        task_id = str(self._next_task_id)
        self._next_task_id += 1
        self._tasks[task_id] = {
            "sha256": sha256,
            "name": path.name,
        }
        logger.info(
            "MockSandboxClient: submitted '%s' -> task_id=%s (sha256=%s)",
            path.name, task_id, sha256[:12],
        )
        return task_id

    def wait_for_completion(
        self,
        task_id: str,
        timeout_seconds: int = 300,
        poll_interval_seconds: int = 10,
    ) -> str:
        """Immediately return 'reported' — mocks are always instant."""
        if task_id not in self._tasks:
            raise SandboxError(f"Unknown task_id: {task_id}")
        logger.info("MockSandboxClient: task %s -> reported (instant).", task_id)
        return "reported"

    def fetch_report(self, task_id: str) -> SubmissionResult:
        """Return a SubmissionResult loaded from a fixture file.

        Fixture lookup order:
          1. <fixtures_dir>/dynamic/<sha256>.json
          2. <fixtures_dir>/dynamic/<name>.json  (without extension)
          3. default_dynamic_fixture (if configured)
          4. Minimal synthetic report

        Args:
            task_id: Task ID returned by submit().

        Returns:
            SubmissionResult with report dict populated from the fixture.

        Raises:
            SandboxError: When task_id is unknown.
        """
        if task_id not in self._tasks:
            raise SandboxError(f"Unknown task_id: {task_id}")

        meta = self._tasks[task_id]
        sha256 = meta["sha256"]
        name = meta["name"]

        report = self._load_fixture(sha256, name)

        return SubmissionResult(
            task_id=task_id,
            sample_sha256=sha256,
            sample_name=name,
            status="reported",
            report=report,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_fixture(self, sha256: str, name: str) -> dict[str, Any]:
        """Attempt to load a fixture in priority order."""
        candidates: list[Path] = [
            self._fixtures_dir / "dynamic" / f"{sha256}.json",
            self._fixtures_dir / "dynamic" / f"{Path(name).stem}.json",
        ]
        if self._default_fixture:
            candidates.append(self._default_fixture)

        for candidate in candidates:
            if candidate.exists():
                logger.info("MockSandboxClient: loading fixture '%s'.", candidate)
                with open(candidate, encoding="utf-8") as f:
                    return json.load(f)

        logger.warning(
            "MockSandboxClient: no fixture found for sha256=%s name=%s. "
            "Returning minimal synthetic report.",
            sha256[:12],
            name,
        )
        return self._minimal_report(sha256, name)

    @staticmethod
    def _minimal_report(sha256: str, name: str) -> dict[str, Any]:
        """Return a structurally valid but empty sandbox report."""
        return {
            "target": {"sha256": sha256, "name": name, "md5": ""},
            "behavior": {
                "apistats": {},
                "generic": [],
                "network": [],
                "processes": [],
            },
            "signatures": [],
        }

    @staticmethod
    def _sha256(path: Path) -> str:
        """Compute SHA-256 of a file."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
