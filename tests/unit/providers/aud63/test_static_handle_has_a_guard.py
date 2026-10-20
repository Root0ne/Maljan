"""PS-L12: a static provider's handle has a guard that limits only what the operator set."""

from __future__ import annotations

from maljan.core.config import Settings
from maljan.providers.server_guard import ServerGuard
from maljan.providers.static.r2 import R2StaticProvider


def test_defaults_set_no_deadline_cap_or_rest():
    guard = R2StaticProvider.from_settings(Settings(_env_file=None))._handle.guard
    assert isinstance(guard, ServerGuard)
    assert guard.call_timeout("analyze") is None
    assert guard.max_concurrent_calls == 0
    for _ in range(50):
        guard.failed("boom")
    assert guard.failures_to_open > 50


def test_operator_settings_are_applied():
    cfg = Settings(_env_file=None)
    cfg.mcp.breaker.call_timeout_seconds = 100
    cfg.mcp.breaker.max_concurrent_calls = 2
    guard = R2StaticProvider.from_settings(cfg)._handle.guard
    assert guard.call_timeout("analyze") is not None and guard.call_timeout("analyze") >= 100
    assert guard.max_concurrent_calls == 2


def test_a_static_rest_is_announced_and_listed_in_server_rests():
    from maljan.core.container import ServiceContainer

    seen: list[tuple[str, dict]] = []
    cfg = Settings(_env_file=None)
    cfg.mcp.breaker.failures_to_open = 1
    container = ServiceContainer(cfg, event_sink=lambda kind, payload: seen.append((kind, payload)))
    provider = R2StaticProvider.from_settings(cfg)
    provider.event_sink = container.event_sink
    container._static_provider_cache["r2"] = provider
    provider._handle.guard.failed("server gone")
    assert [r["server"] for r in container.server_rests()] == ["r2"]
    assert seen and seen[0][1]["server"] == "r2"
