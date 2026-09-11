"""``build_settings`` is store-only: no environment, no ``.env``, ever.

Task 3 of the env-free configuration work removes the environment as a layer
for the application. ``build_settings`` is the one construction path the
application (API, worker) may use -- see
``tests/unit/test_no_bare_settings_in_app.py`` for the architecture guard.
The bare ``Settings()`` constructor is untouched by this and stays
environment- and dotenv-capable.
"""

from __future__ import annotations

from maljan.core import settings_overrides as ov
from maljan.core.config import LLMConfig, Settings


def test_build_settings_ignores_the_process_environment(monkeypatch):
    monkeypatch.setenv("LLM__PROVIDER", "anthropic")
    s = ov.build_settings({})
    assert s.llm.provider != "anthropic"
    assert s.llm.provider == LLMConfig().provider


def test_build_settings_ignores_a_dotenv_file_bare_settings_would_read(tmp_path, monkeypatch):
    """``model_config["env_file"]`` is the absolute path ``_find_env_file()``
    resolved at class-definition time, so a plain ``.env`` dropped in the
    CWD is never on that path -- even a bare ``Settings()`` would not read
    it, which would make a CWD-only ``.env`` a vacuous target for this test.
    Point the discovered file at the fixture's ``.env`` instead: bare
    ``Settings()`` reads it (the control, proving the file is actually
    wired in), and ``build_settings`` must still not.
    """
    env_file = tmp_path / ".env"
    env_file.write_text("LLM__PROVIDER=anthropic\n")
    monkeypatch.setitem(Settings.model_config, "env_file", str(env_file))

    assert Settings().llm.provider == "anthropic"
    assert ov.build_settings({}).llm.provider != "anthropic"


def test_build_settings_still_applies_explicit_overrides(monkeypatch):
    monkeypatch.setenv("LLM__PROVIDER", "anthropic")
    s = ov.build_settings({"llm.provider": "ollama"})
    assert s.llm.provider == "ollama"


def test_bare_settings_still_honours_the_environment(monkeypatch):
    """Documented library behaviour: only ``build_settings`` is store-only."""
    monkeypatch.setenv("LLM__PROVIDER", "anthropic")
    s = Settings(_env_file=None)
    assert s.llm.provider == "anthropic"


def test_effective_source_reflects_only_whether_a_row_exists():
    assert ov.effective_source(overridden=True) == "ui"
    assert ov.effective_source(overridden=False) == "default"
