"""PS-L4: the CLI overwrites llm.provider and max_iterations only when asked to."""

from __future__ import annotations

from typing import Any

from typer.testing import CliRunner

from maljan import cli
from maljan.core.config import Settings


def _run(monkeypatch, args: list[str]) -> Settings:
    cfg = Settings(_env_file=None)
    cfg.llm.provider = "anthropic"
    cfg.negotiation.max_iterations = 7
    seen: dict[str, Any] = {}

    class _App:
        def __init__(self, config: Settings, mock: bool, **_options: Any) -> None:
            seen["config"] = config
            raise RuntimeError("stop")

    monkeypatch.setattr(cli, "_settings", lambda: cfg)
    monkeypatch.setattr(cli, "MaljanApp", _App)
    monkeypatch.setattr(cli, "_release", lambda app: None)
    CliRunner().invoke(cli.app, ["analyze", "abc", *args])
    return seen["config"]


def test_unset_options_keep_the_configured_values(monkeypatch):
    config = _run(monkeypatch, [])
    assert config.llm.provider == "anthropic"
    assert config.negotiation.max_iterations == 7


def test_given_options_replace_them(monkeypatch):
    config = _run(monkeypatch, ["-i", "3"])
    assert config.negotiation.max_iterations == 3
