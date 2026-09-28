"""The command line's app masks the secrets its settings hold, as the worker does.

``maljan analyze`` builds a ``MaljanApp`` and runs the same pipeline the
worker runs, with the same scrub over its events, finding rows and report; the
configured secrets are handed to that scrub when the app is built.
"""

from __future__ import annotations

from maljan.app import MaljanApp
from maljan.core.config import Settings
from maljan.pipeline import events as ev
from tests.credential_shapes import lowercase_body


def _passphrase() -> str:
    letters = "".join(char for char in lowercase_body(72) if char.isalpha())
    return "-".join([letters[0:7], letters[7:13], "stable"])


def test_building_the_app_registers_its_configured_secrets() -> None:
    secret = _passphrase()
    assert ev.scrub(f"used {secret}") == f"used {secret}"

    MaljanApp(config=Settings.model_validate({"llm": {"openai": {"api_key": secret}}}), mock=True)

    assert ev.scrub(f"used {secret}") == "used ***"
