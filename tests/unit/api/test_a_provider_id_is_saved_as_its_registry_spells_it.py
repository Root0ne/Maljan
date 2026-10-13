"""A provider id is saved and submitted only as its registry spells it.

A value that differs in case or spacing names no provider when a job is built,
so it is refused where it is saved and where a job is submitted, never stored
for every job to fail on. Reading the settings and the catalogue for the
shipped providers loads no client library a model has not been built with.
"""

from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from app.schemas.job import JobCreateRequest
from app.services.settings_service import SettingsService, SettingsValidationError
from maljan.llm import registry
from maljan.llm.provider_base import _FACTS, LLMProvider, provider_names
from maljan.memory.store_factory import memory_backends
from maljan.providers.registry import sandbox_provider_ids, static_provider_ids

ROOT = Path(__file__).resolve().parents[3]

MISSPELT = [
    ("core.sandbox.provider", "CAPE2"),
    ("core.static.provider", " R2 "),
    ("core.llm.provider", "OpenAI"),
    ("core.memory.backend", "Qdrant"),
]


def _service() -> SettingsService:
    return SettingsService(db=None)  # type: ignore[arg-type]


@pytest.mark.parametrize(("key", "value"), MISSPELT)
def test_a_misspelt_id_is_refused_at_save(key: str, value: str) -> None:
    with pytest.raises(SettingsValidationError) as refused:
        _service().check_keys({key: value}, {})
    assert key in refused.value.errors


def test_every_shipped_id_is_accepted_at_save() -> None:
    for key, ids in (
        ("core.static.provider", static_provider_ids()),
        ("core.sandbox.provider", sandbox_provider_ids()),
        ("core.llm.provider", provider_names()),
        ("core.memory.backend", list(memory_backends())),
    ):
        assert ids
        for provider in ids:
            assert _service().check_keys({key: provider}, {}) is None, (key, provider)


@pytest.mark.parametrize(
    ("field", "value"),
    [("sandbox_provider", "CAPE2"), ("static_provider", " R2 "), ("llm_provider", "OpenAI")],
)
def test_a_misspelt_id_is_refused_at_submit(field: str, value: str) -> None:
    from app.worker.analysis_worker import build_job_settings

    with pytest.raises(ValidationError):
        JobCreateRequest(sample_id=uuid.uuid4(), config={field: value})
    with pytest.raises(ValidationError):
        build_job_settings({}, {field: value})


class _Bare(LLMProvider):
    """A registered provider whose adapter declares no settings block."""

    name = "bare"

    def __init__(self, config: Any) -> None:
        self._config = config


def test_a_provider_with_no_settings_block_is_refused_for_a_job() -> None:
    from app.worker.analysis_worker import build_job_settings

    registry.discover_providers()
    registry.register_provider("bare")(_Bare)
    try:
        with pytest.raises(ValidationError, match="no settings block"):
            JobCreateRequest(sample_id=uuid.uuid4(), config={"llm_provider": "bare"})
        with pytest.raises(ValidationError, match="no settings block"):
            build_job_settings({}, {"llm_provider": "bare"})
        # Selected by the stored settings rather than the job: never run with
        # an empty model name.
        with pytest.raises(ValueError, match="no settings block"):
            build_job_settings({"llm.provider": "bare"}, {})
    finally:
        registry._PROVIDER_REGISTRY.pop("bare", None)
        _FACTS.pop("bare", None)


def _loads_gemini_client(code: str) -> bool:
    script = f"{code}\nimport sys\nprint('langchain_google_genai' in sys.modules)"
    done = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env={
            "PATH": "/usr/bin:/bin",
            "PYTHONPATH": f"{ROOT / 'src'}:{ROOT / 'apps' / 'api'}",
            "HOME": "/nonexistent",
        },
        timeout=300,
        check=True,
    )
    return done.stdout.strip().splitlines()[-1] == "True"


def test_a_save_of_the_shipped_names_loads_no_unused_client_library() -> None:
    code = (
        "from app.services.settings_service import SettingsService\n"
        "SettingsService(db=None).check_keys({'core.llm.provider': 'openai'}, {})"
    )
    assert _loads_gemini_client(code) is False


def test_importing_the_worker_loads_no_unused_client_library() -> None:
    assert _loads_gemini_client("import app.worker.analysis_worker") is False
