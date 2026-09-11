"""The application never constructs ``Settings``/``APISettings`` bare.

Task 3 of the env-free configuration work makes the environment stop being a
layer for the application: the API and the worker build their core settings
through ``build_settings`` (store overrides + model defaults only), never
through a bare ``Settings()``/``Settings(_env_file=...)``/``APISettings()``
call. Two places are allowed to construct bare regardless:

- ``apps/api/app/config.py`` -- the lazy ``APISettings()`` singleton
  (``get_settings()``'s memoised factory); it is process-environment-only by
  design (Task 1) and is not the core-settings path this task narrows.
- ``apps/api/app/services/legacy_env_import.py`` -- a future one-shot import
  tool that reads the legacy ``.env`` into the store; it necessarily
  constructs a bare, environment-reading ``Settings`` to do that. Kept in the
  allow-list even though the file does not exist yet.

The regex is bare-call-only (``Settings()``, ``Settings(_env_file=...)``,
``APISettings()``) so a kwargs construction such as
``APISettings(**nest(merged_api))`` does not trip it -- that is validating
supplied values, not reading the environment.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = ROOT / "apps" / "api" / "app"

_BARE_CONSTRUCTION = re.compile(r"\bSettings\(\)|\bAPISettings\(\)|Settings\(_env_file")

_ALLOWED_FILES = {
    "config.py",
    "services/legacy_env_import.py",
}


def _tracked_app_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "apps/api/app"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [ROOT / rel for rel in out if rel.endswith(".py")]


def test_there_are_python_files_to_check() -> None:
    assert len(_tracked_app_files()) > 20


def test_no_bare_settings_construction_outside_the_allow_list() -> None:
    offenders: list[str] = []
    for path in _tracked_app_files():
        rel = path.relative_to(APP_ROOT) if path.is_relative_to(APP_ROOT) else None
        if rel is not None and str(rel) in _ALLOWED_FILES:
            continue
        if not path.is_file():
            # legacy_env_import.py is allow-listed before it exists.
            continue
        text = path.read_text(encoding="utf-8")
        if _BARE_CONSTRUCTION.search(text):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == [], (
        "bare Settings()/APISettings() construction outside the allow-list: "
        f"{offenders} -- use build_settings(...) for core settings"
    )


def test_the_worker_builds_core_settings_through_build_settings() -> None:
    worker = APP_ROOT / "worker" / "analysis_worker.py"
    text = worker.read_text(encoding="utf-8")
    assert "build_settings(" in text
    assert not _BARE_CONSTRUCTION.search(text)
