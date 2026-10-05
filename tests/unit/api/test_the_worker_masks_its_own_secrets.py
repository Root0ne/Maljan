"""The worker masks the secrets it holds, by value, in everything it publishes.

A passphrase an operator configured reads as words to every shape rule the
scrub has, so the worker hands the scrub the values themselves: the model and
tool keys of the job's settings and its own database, Redis and object-store
credentials.
"""

from __future__ import annotations

from typing import Any

from pydantic import SecretStr
from tests.credential_shapes import lowercase_body, password

from app.config import APISettings as ApiSettings
from app.worker import analysis_worker
from maljan.core.config import Settings
from maljan.pipeline import events as ev


def _passphrase(variant: int) -> str:
    letters = "".join(char for char in lowercase_body(72) if char.isalpha())
    start = 6 * variant
    return "-".join([letters[start : start + 6], letters[start + 6 : start + 12], "stable"])


def test_the_job_s_secrets_and_the_worker_s_own_are_masked(monkeypatch: Any) -> None:
    model_key, store_secret, db_password = _passphrase(0), _passphrase(1), password(18)
    core = Settings.model_validate({"llm": {"openai": {"api_key": model_key}}})

    api = ApiSettings(
        minio_secret_key=SecretStr(store_secret),
        database_url="postgresql+asyncpg://maljan:" + db_password + "@db:5432/maljan",
    )
    monkeypatch.setattr(analysis_worker, "get_settings", lambda: api)

    analysis_worker.remember_process_secrets()
    analysis_worker.remember_configured_secrets(core)

    published = analysis_worker.scrubbed(
        {"text": f"tried {model_key}, then {store_secret} and {db_password}"}
    )
    assert published == {"text": "tried ***, then *** and ***"}


def test_a_job_s_settings_replace_the_previous_job_s(monkeypatch: Any) -> None:
    """A secret no longer configured is not masked in a later job; the worker's own still is."""
    old_key, new_key, store_secret = _passphrase(0), _passphrase(1), _passphrase(2)
    api = ApiSettings(minio_secret_key=SecretStr(store_secret))
    monkeypatch.setattr(analysis_worker, "get_settings", lambda: api)
    analysis_worker.remember_process_secrets()

    analysis_worker.remember_configured_secrets(
        Settings.model_validate({"llm": {"openai": {"api_key": old_key}}})
    )
    analysis_worker.remember_configured_secrets(
        Settings.model_validate({"llm": {"openai": {"api_key": new_key}}})
    )

    assert ev.scrub(f"{old_key} {new_key} {store_secret}") == f"{old_key} *** ***"


def test_a_job_starts_with_no_names_the_previous_job_resolved() -> None:
    """The names one job's hash resolution read are kept as written for that job alone."""
    name = "SyntheticResolvedExport32NameW"
    ev.remember_resolved_names({"hits": [{"readings": [{"set": "exports", "name": name}]}]})
    assert ev.scrub(name) == name

    analysis_worker.remember_configured_secrets(Settings.model_validate({}))

    assert ev.scrub(name) == "***"
