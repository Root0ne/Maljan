"""Shared access to a real-shaped CAPE2 report for the provider tests.

``data/cape_reports/`` is a git-ignored directory of real CAPE reports kept
locally for development; it is not present on CI runners. Tests that need a
CAPE2-shaped payload should go through :func:`first_cape_report_path` or
:func:`first_cape_report` rather than globbing ``data/cape_reports`` directly,
so they fall back to the small, committed fixture at
``tests/fixtures/sandbox/cape2_report.json`` when the real directory is
missing or empty.

Set the environment variable ``MALJAN_TEST_NO_CAPE_REPORTS=1`` to force the
fallback path even on a machine that does have the real reports — useful for
proving the fallback works without deleting anything.
"""

from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "sandbox" / "cape2_report.json"


def _no_real_reports_forced() -> bool:
    return os.environ.get("MALJAN_TEST_NO_CAPE_REPORTS") == "1"


def first_cape_report_path() -> Path:
    """Return a path to a CAPE2-shaped report: real if available, else the fixture."""
    if not _no_real_reports_forced():
        candidates = sorted((ROOT / "data" / "cape_reports").glob("*.json"))
        if candidates:
            return candidates[0]
    return FIXTURE_PATH


def first_cape_report() -> dict:
    """Return the parsed JSON of :func:`first_cape_report_path`."""
    import json

    return json.loads(first_cape_report_path().read_text(encoding="utf-8"))
