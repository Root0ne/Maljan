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

Fix round 1 (Critical 2/3) found the same leak could come back through
``maljan.core.config.get_settings()``, the module-level lazy singleton:
``apps/api/app/api/v1/sandbox_reports.py`` and
``apps/api/app/worker/sample_files.py`` called it directly from a request
path that never installs it, so on first access in a fresh process it fell
back to a bare, environment-reading ``Settings()`` -- invisible to the regex
above, since the string ``Settings()`` never appears. The second check below
guards against that: a file may not import ``get_settings`` from
``maljan.core.config`` and then call it bare. It is careful to look for the
*core* module's ``get_settings`` specifically -- ``app.config.get_settings``
(the API's own, process-environment-only ``APISettings`` singleton; a
different function, same name) is unaffected and stays common throughout
``apps/api/app``.
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

# A file matches this only when it actually names *the core module's*
# ``get_settings`` -- either by importing the bare name from
# ``maljan.core.config`` or by reaching it through a qualified
# ``core.config.get_settings`` access (e.g. an aliased ``import ... as
# core_config`` followed by ``core_config.get_settings``). A file that never
# does either (in particular one that only imports ``get_settings`` from
# ``app.config``, the API's own) never reaches the second, unqualified
# ``get_settings()``-call check -- so that call, wherever it is imported
# from, is never flagged as the core one by mistake.
_IMPORTS_CORE_GET_SETTINGS = re.compile(
    r"from maljan\.core\.config import[^\n]*\bget_settings\b|core\.config\.get_settings"
)
_BARE_GET_SETTINGS_CALL = re.compile(r"\bget_settings\(\)")

# No legitimate job-path use was found: every job-path reader of the process
# singleton (agents, pipeline nodes, extractors, the CLI) lives under
# src/maljan, not apps/api/app, and the two request-path call sites this
# review round found (sandbox_reports.py, sample_files.py) are fixed instead
# of allow-listed. Empty on purpose -- see the module docstring.
_GET_SETTINGS_ALLOWED_FILES: set[str] = set()


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


def test_no_core_get_settings_outside_the_allow_list() -> None:
    offenders: list[str] = []
    for path in _tracked_app_files():
        rel = path.relative_to(APP_ROOT) if path.is_relative_to(APP_ROOT) else None
        if rel is not None and str(rel) in _GET_SETTINGS_ALLOWED_FILES:
            continue
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if _IMPORTS_CORE_GET_SETTINGS.search(text) and _BARE_GET_SETTINGS_CALL.search(text):
            offenders.append(str(path.relative_to(ROOT)))
    assert offenders == [], (
        "maljan.core.config.get_settings() called outside the allow-list: "
        f"{offenders} -- it is a lazy, environment-reading singleton on a "
        "request path that never installs it; read through "
        "settings_service.effective_core_settings(db) (or, inside a job "
        "after install_settings, get_settings() there is the installed "
        "store-backed instance and is fine) instead"
    )
