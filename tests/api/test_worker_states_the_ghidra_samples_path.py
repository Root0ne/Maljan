"""The worker says, at start, which Ghidra samples path it hands Ghidra and why.

``GHIDRA_CONTAINER_SAMPLES_PATH`` is the samples directory as the Ghidra
container sees it. Set to the host directory instead, every load answered
"File not found" from inside the container and nothing at start said which
path the worker was using or where it came from.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from app.config import APISettings
from app.worker import analysis_worker


class _Stop(Exception):
    """Ends ``startup`` right after the line, before any database or Redis."""


def test_the_default_is_named_as_the_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GHIDRA_CONTAINER_SAMPLES_PATH", raising=False)
    line = analysis_worker.ghidra_samples_path_line(APISettings())
    assert "Ghidra samples path: /data/samples " in line
    assert "the default; GHIDRA_CONTAINER_SAMPLES_PATH is not set" in line


def test_a_value_from_the_environment_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GHIDRA_CONTAINER_SAMPLES_PATH", "/srv/maljan/data/samples")
    line = analysis_worker.ghidra_samples_path_line(APISettings())
    assert "Ghidra samples path: /srv/maljan/data/samples (from GHIDRA_CONTAINER_SAMPLES_PATH)" in (
        line
    )
    assert "as the Ghidra container sees it" in line


def test_startup_states_it_once(monkeypatch: pytest.MonkeyPatch) -> None:
    log = MagicMock()
    monkeypatch.setattr(analysis_worker, "logger", log)
    monkeypatch.setattr(analysis_worker, "setup_logging", lambda: None)
    monkeypatch.setattr("app.bootstrap.require_bootstrap", lambda _settings: None)

    def stop(_overrides: object) -> None:
        raise _Stop

    monkeypatch.setattr(analysis_worker, "build_settings", stop)

    with pytest.raises(_Stop):
        asyncio.run(analysis_worker.startup({}))

    said = [call.args[0] for call in log.info.call_args_list]
    assert sum(1 for text in said if text.startswith("Ghidra samples path: ")) == 1
