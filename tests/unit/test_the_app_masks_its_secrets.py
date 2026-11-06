"""The command line's app masks the secrets its settings hold, as the worker does.

``malspark analyze`` builds a ``MalsparkApp`` and runs the same pipeline the
worker runs, with the same scrub over its events, finding rows and report; the
configured secrets are handed to that scrub when the app is built.
"""

from __future__ import annotations

from malspark.app import MalsparkApp
from malspark.core.config import Settings
from malspark.pipeline import events as ev
from tests.credential_shapes import lowercase_body


def _passphrase() -> str:
    letters = "".join(char for char in lowercase_body(72) if char.isalpha())
    return "-".join([letters[0:7], letters[7:13], "stable"])


def test_building_the_app_registers_its_configured_secrets() -> None:
    secret = _passphrase()
    assert ev.scrub(f"used {secret}") == f"used {secret}"

    MalsparkApp(config=Settings.model_validate({"llm": {"openai": {"api_key": secret}}}), mock=True)

    assert ev.scrub(f"used {secret}") == "used ***"


def test_an_app_built_by_the_worker_leaves_the_registration_to_it() -> None:
    """The worker registers a job's settings itself; its app does not register them twice."""
    secret = _passphrase()

    MalsparkApp(
        config=Settings.model_validate({"llm": {"openai": {"api_key": secret}}}),
        mock=True,
        remember_secrets=False,
    )

    assert ev.scrub(f"used {secret}") == f"used {secret}"
