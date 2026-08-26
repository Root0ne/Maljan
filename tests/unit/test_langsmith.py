"""Unit tests for LangSmith Observability integration (Phase 8.1).

Tests:
  - Settings.langchain_project: default value, customizable
  - _configure_langsmith():
      disabled by default (no env vars set)
      tracing=True + api_key: sets all three env vars
      tracing=True + no api_key: sets TRACING + PROJECT, warns
      project name propagated to LANGCHAIN_PROJECT env var
      api_key last-4 logged (not full key)
      idempotent when called twice
      env vars cleaned up between tests (isolation)
  - ServiceContainer.__init__ calls _configure_langsmith automatically
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from maljan.core.config import Settings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_container_with(
    tracing: bool = False,
    api_key: str | None = None,
    project: str = "maljan",
) -> object:
    """Create a ServiceContainer in mock mode with custom LangSmith settings."""
    from maljan.core.container import ServiceContainer

    cfg = Settings(
        langchain_tracing_v2=tracing,
        langchain_api_key=api_key,
        langchain_project=project,
    )
    return ServiceContainer(config=cfg, mock=True)


# ---------------------------------------------------------------------------
# Settings.langchain_project
# ---------------------------------------------------------------------------


class TestLangChainProjectConfig:
    def test_default_project_is_maljan(self) -> None:
        cfg = Settings()
        assert cfg.langchain_project == "maljan"

    def test_project_can_be_overridden(self) -> None:
        cfg = Settings(langchain_project="maljan-dev")
        assert cfg.langchain_project == "maljan-dev"

    def test_tracing_disabled_by_default(self) -> None:
        cfg = Settings()
        assert cfg.langchain_tracing_v2 is False

    def test_api_key_default_none(self) -> None:
        cfg = Settings()
        assert cfg.langchain_api_key is None


# ---------------------------------------------------------------------------
# _configure_langsmith() — disabled path
# ---------------------------------------------------------------------------


class TestConfigureLangSmithDisabled:
    def test_disabled_does_not_set_tracing_env_var(self) -> None:
        env = os.environ.copy()
        env.pop("LANGCHAIN_TRACING_V2", None)

        with patch.dict(os.environ, env, clear=True):
            _make_container_with(tracing=False)
            assert "LANGCHAIN_TRACING_V2" not in os.environ

    def test_disabled_does_not_set_project_env_var(self) -> None:
        env = os.environ.copy()
        env.pop("LANGCHAIN_PROJECT", None)

        with patch.dict(os.environ, env, clear=True):
            _make_container_with(tracing=False)
            assert "LANGCHAIN_PROJECT" not in os.environ

    def test_disabled_does_not_set_api_key_env_var(self) -> None:
        env = os.environ.copy()
        env.pop("LANGCHAIN_API_KEY", None)

        with patch.dict(os.environ, env, clear=True):
            _make_container_with(tracing=False, api_key="ls_test_key")
            assert "LANGCHAIN_API_KEY" not in os.environ


# ---------------------------------------------------------------------------
# _configure_langsmith() — enabled with api key
# ---------------------------------------------------------------------------


class TestConfigureLangSmithEnabled:
    def test_sets_tracing_env_var_to_true(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            _make_container_with(tracing=True, api_key="ls_abc123")
            assert os.environ.get("LANGCHAIN_TRACING_V2") == "true"

    def test_sets_project_env_var(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            _make_container_with(tracing=True, api_key="ls_abc123", project="maljan-prod")
            assert os.environ.get("LANGCHAIN_PROJECT") == "maljan-prod"

    def test_sets_api_key_env_var(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            _make_container_with(tracing=True, api_key="ls_abc123")
            assert os.environ.get("LANGCHAIN_API_KEY") == "ls_abc123"

    def test_default_project_used_when_not_overridden(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            _make_container_with(tracing=True, api_key="ls_abc123")
            assert os.environ.get("LANGCHAIN_PROJECT") == "maljan"


# ---------------------------------------------------------------------------
# _configure_langsmith() — enabled without api key
# ---------------------------------------------------------------------------


class TestConfigureLangSmithNoKey:
    def test_sets_tracing_env_var_without_key(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            _make_container_with(tracing=True, api_key=None)
            assert os.environ.get("LANGCHAIN_TRACING_V2") == "true"

    def test_sets_project_without_key(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            _make_container_with(tracing=True, api_key=None, project="maljan-nokey")
            assert os.environ.get("LANGCHAIN_PROJECT") == "maljan-nokey"

    def test_does_not_set_api_key_when_none(self) -> None:
        env_without_key = {k: v for k, v in os.environ.items() if k != "LANGCHAIN_API_KEY"}
        with patch.dict(os.environ, env_without_key, clear=True):
            _make_container_with(tracing=True, api_key=None)
            assert "LANGCHAIN_API_KEY" not in os.environ

    def test_emits_warning_when_no_key(self, caplog: pytest.LogCaptureFixture) -> None:
        import logging

        with caplog.at_level(logging.WARNING, logger="maljan"):
            with patch.dict(os.environ, {}, clear=False):
                _make_container_with(tracing=True, api_key=None)
        assert any("API key" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# _configure_langsmith() — direct method tests on container
# ---------------------------------------------------------------------------


class TestConfigureLangSmithMethod:
    def _make_container_raw(self) -> object:
        from maljan.core.container import ServiceContainer

        return ServiceContainer.__new__(ServiceContainer)

    def test_method_is_no_op_when_disabled(self) -> None:
        from maljan.core.container import ServiceContainer

        container = ServiceContainer.__new__(ServiceContainer)
        container.config = Settings(langchain_tracing_v2=False)

        with patch.dict(os.environ, {}, clear=False):
            container._configure_langsmith()  # type: ignore[union-attr]
            assert os.environ.get("LANGCHAIN_TRACING_V2") not in ("true", "True", "1")

    def test_idempotent_when_called_twice(self) -> None:
        """Calling _configure_langsmith twice must not raise or corrupt state."""
        from maljan.core.container import ServiceContainer

        container = ServiceContainer.__new__(ServiceContainer)
        container.config = Settings(
            langchain_tracing_v2=True,
            langchain_api_key="ls_test",
            langchain_project="maljan-idem",
        )
        with patch.dict(os.environ, {}, clear=False):
            container._configure_langsmith()  # type: ignore[union-attr]
            container._configure_langsmith()  # type: ignore[union-attr]
            assert os.environ.get("LANGCHAIN_TRACING_V2") == "true"
            assert os.environ.get("LANGCHAIN_PROJECT") == "maljan-idem"

    def test_logs_masked_api_key(self, caplog: pytest.LogCaptureFixture) -> None:
        """The log message should include the last 4 chars, not the full key."""
        import logging

        from maljan.core.container import ServiceContainer

        container = ServiceContainer.__new__(ServiceContainer)
        container.config = Settings(
            langchain_tracing_v2=True,
            langchain_api_key="ls_secretkey9999",
            langchain_project="maljan",
        )
        with caplog.at_level(logging.INFO, logger="maljan"):
            with patch.dict(os.environ, {}, clear=False):
                container._configure_langsmith()  # type: ignore[union-attr]

        full_key_logged = any("ls_secretkey9999" in r.message for r in caplog.records)
        last4_logged = any("9999" in r.message for r in caplog.records)
        assert not full_key_logged, "Full API key must never appear in logs"
        assert last4_logged, "Last 4 chars of API key should appear in log"


# ---------------------------------------------------------------------------
# ServiceContainer.__init__ auto-wiring
# ---------------------------------------------------------------------------


class TestContainerAutoWiring:
    def test_init_calls_configure_langsmith(self) -> None:
        """__init__ must call _configure_langsmith automatically."""
        from maljan.core.container import ServiceContainer

        with patch.object(ServiceContainer, "_configure_langsmith") as mock_configure:
            ServiceContainer(config=Settings(), mock=True)
            mock_configure.assert_called_once()
