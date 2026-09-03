"""Unit tests for the Redis-backed rate limiting middleware."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.middleware.rate_limit_middleware import RateLimitMiddleware
from starlette.requests import Request
from starlette.responses import Response

pytestmark = pytest.mark.asyncio


@pytest.fixture
def mock_app():
    """Minimal ASGI app for middleware testing."""

    async def app(scope, receive, send):
        response = Response(content='{"ok":true}', status_code=200)
        await response(scope, receive, send)

    return app


@pytest.fixture
def fake_redis():
    """In-memory fake Redis for isolated tests."""
    from fakeredis.aioredis import FakeRedis

    return FakeRedis()


def _patch_runtime_config(
    *,
    enabled: bool = True,
    max_requests: int = 100,
    window_seconds: int = 60,
    trusted_proxy_ips: list[str] | None = None,
):
    """Rate limits now come from ``runtime_config`` rather than constructor
    attributes (Task 7: live api.* overrides). Tests exercise ``dispatch``
    directly, so the values that used to live on ``self`` are supplied
    through a patched ``runtime_config.get`` instead.
    """
    values = {
        "rate_limit_enabled": enabled,
        "rate_limit_requests": max_requests,
        "rate_limit_window_seconds": window_seconds,
        "trusted_proxy_ips": trusted_proxy_ips or [],
    }

    async def _get(name: str):
        return values[name]

    return patch(
        "app.middleware.rate_limit_middleware.runtime_config.get",
        AsyncMock(side_effect=_get),
    )


def _install_counter(middleware: RateLimitMiddleware) -> dict[str, int]:
    """Replace the Lua-based incrementer with a pure-Python counter.

    ``fakeredis.aioredis.FakeRedis`` does not support the ``EVAL`` command
    so the production code's atomic INCR+TTL Lua script always falls through
    to the "fail-open" branch (returning ``(0, window)``). For unit tests we
    swap in a tiny dict-backed counter that mirrors the script's contract.
    """
    counts: dict[str, int] = {}

    async def fake_incr(redis_client, key, window_seconds):
        counts[key] = counts.get(key, 0) + 1
        return counts[key], window_seconds

    middleware._incr_with_ttl = fake_incr  # type: ignore[method-assign]
    return counts


class TestRateLimitMiddleware:
    """Tests for RateLimitMiddleware dispatch logic."""

    async def test_request_allowed_when_under_limit(self, mock_app, fake_redis):
        """Request proceeds normally when under the rate limit."""
        middleware = RateLimitMiddleware(
            mock_app,
            redis_url="redis://localhost:6379/0",
            whitelist=[],
        )
        # Replace with fake Redis for testing
        middleware._redis_pool = fake_redis.connection_pool
        _install_counter(middleware)

        request = Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "http",
                "server": ("test", 80),
                "path": "/api/v1/samples",
                "query_string": b"",
                "headers": [],
                "client": ("192.168.1.1", 12345),
            }
        )

        async def call_next(req):
            return Response(content='{"ok":true}', status_code=200)

        with _patch_runtime_config(max_requests=10, window_seconds=60):
            response = await middleware.dispatch(request, call_next)

        assert response.status_code == 200
        assert response.headers["X-RateLimit-Limit"] == "10"
        assert int(response.headers["X-RateLimit-Remaining"]) == 9
        assert int(response.headers["X-RateLimit-Reset"]) <= 60

    async def test_request_blocked_when_limit_exceeded(self, mock_app, fake_redis):
        """429 returned when request count exceeds the limit."""
        middleware = RateLimitMiddleware(
            mock_app,
            redis_url="redis://localhost:6379/0",
            whitelist=[],
        )
        middleware._redis_pool = fake_redis.connection_pool
        _install_counter(middleware)

        request = Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "http",
                "server": ("test", 80),
                "path": "/api/v1/jobs",
                "query_string": b"",
                "headers": [],
                "client": ("192.168.1.2", 12345),
            }
        )

        async def call_next(req):
            return Response(content='{"ok":true}', status_code=200)

        with _patch_runtime_config(max_requests=2, window_seconds=60):
            # First two requests succeed
            response1 = await middleware.dispatch(request, call_next)
            assert response1.status_code == 200

            response2 = await middleware.dispatch(request, call_next)
            assert response2.status_code == 200

            # Third request is blocked
            response3 = await middleware.dispatch(request, call_next)
        assert response3.status_code == 429
        assert response3.headers["Retry-After"]
        assert response3.headers["X-RateLimit-Remaining"] == "0"

    async def test_whitelisted_paths_not_limited(self, mock_app, fake_redis):
        """Paths in whitelist bypass rate limiting entirely."""
        middleware = RateLimitMiddleware(
            mock_app,
            redis_url="redis://localhost:6379/0",
            whitelist=["/health"],
        )
        middleware._redis_pool = fake_redis.connection_pool

        request = Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "http",
                "server": ("test", 80),
                "path": "/health",
                "query_string": b"",
                "headers": [],
                "client": ("192.168.1.3", 12345),
            }
        )

        async def call_next(req):
            return Response(content='{"ok":true}', status_code=200)

        # Multiple requests to whitelisted path should all succeed
        with _patch_runtime_config(max_requests=1, window_seconds=60):
            for _ in range(5):
                response = await middleware.dispatch(request, call_next)
                assert response.status_code == 200

    async def test_disabled_middleware_allows_all(self, mock_app, fake_redis):
        """When disabled, all requests pass through without Redis checks."""
        middleware = RateLimitMiddleware(
            mock_app,
            redis_url="redis://localhost:6379/0",
            whitelist=[],
        )
        middleware._redis_pool = fake_redis.connection_pool

        request = Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "http",
                "server": ("test", 80),
                "path": "/api/v1/jobs",
                "query_string": b"",
                "headers": [],
                "client": ("192.168.1.4", 12345),
            }
        )

        async def call_next(req):
            return Response(content='{"ok":true}', status_code=200)

        # Many requests should all succeed
        with _patch_runtime_config(enabled=False, max_requests=1, window_seconds=60):
            for _ in range(10):
                response = await middleware.dispatch(request, call_next)
                assert response.status_code == 200
                # No rate limit headers when disabled
                assert "X-RateLimit-Limit" not in response.headers

    async def test_graceful_degradation_on_redis_failure(self, mock_app):
        """When Redis fails, request is allowed to proceed."""
        middleware = RateLimitMiddleware(
            mock_app,
            redis_url="redis://invalid:6379/0",
            whitelist=[],
        )

        request = Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "http",
                "server": ("test", 80),
                "path": "/api/v1/jobs",
                "query_string": b"",
                "headers": [],
                "client": ("192.168.1.5", 12345),
            }
        )

        async def call_next(req):
            return Response(content='{"ok":true}', status_code=200)

        # Should NOT raise; should allow request through
        with _patch_runtime_config(max_requests=10, window_seconds=60):
            response = await middleware.dispatch(request, call_next)
        assert response.status_code == 200

    async def test_different_ips_have_separate_counters(self, mock_app, fake_redis):
        """Each IP address has its own independent rate limit counter."""
        middleware = RateLimitMiddleware(
            mock_app,
            redis_url="redis://localhost:6379/0",
            whitelist=[],
        )
        middleware._redis_pool = fake_redis.connection_pool
        _install_counter(middleware)

        async def call_next(req):
            return Response(content='{"ok":true}', status_code=200)

        # IP A exhausts its limit
        req_a = Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "http",
                "server": ("test", 80),
                "path": "/api/v1/jobs",
                "query_string": b"",
                "headers": [],
                "client": ("10.0.0.1", 12345),
            }
        )

        with _patch_runtime_config(max_requests=2, window_seconds=60):
            await middleware.dispatch(req_a, call_next)
            await middleware.dispatch(req_a, call_next)
            blocked = await middleware.dispatch(req_a, call_next)
        assert blocked.status_code == 429

        # IP B should still be allowed
        req_b = Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "http",
                "server": ("test", 80),
                "path": "/api/v1/jobs",
                "query_string": b"",
                "headers": [],
                "client": ("10.0.0.2", 12345),
            }
        )

        with _patch_runtime_config(max_requests=2, window_seconds=60):
            allowed = await middleware.dispatch(req_b, call_next)
        assert allowed.status_code == 200


async def _peer_ip(middleware, peer: str, xff: str | None, trusted: list[str], monkeypatch):
    from app.middleware import rate_limit_middleware as rlm

    async def _get(name):
        return trusted if name == "trusted_proxy_ips" else None

    monkeypatch.setattr(rlm.runtime_config, "get", _get)
    request = MagicMock()
    request.client.host = peer
    request.headers = {"x-forwarded-for": xff} if xff else {}
    return await middleware._extract_client_ip(request)


class TestTrustedProxyNetworks:
    async def test_cidr_matches_a_host_inside_it(self, mock_app, fake_redis, monkeypatch):
        mw = RateLimitMiddleware(mock_app, redis_url="redis://localhost:6379/0", whitelist=[])
        result = await _peer_ip(mw, "10.1.2.3", "203.0.113.9", ["10.0.0.0/8"], monkeypatch)
        assert result == "203.0.113.9"

    async def test_bare_address_matches_itself_only(self, mock_app, fake_redis, monkeypatch):
        mw = RateLimitMiddleware(mock_app, redis_url="redis://localhost:6379/0", whitelist=[])
        result1 = await _peer_ip(mw, "192.168.1.5", "203.0.113.9", ["192.168.1.5"], monkeypatch)
        assert result1 == "203.0.113.9"
        result2 = await _peer_ip(mw, "192.168.1.6", "203.0.113.9", ["192.168.1.5"], monkeypatch)
        assert result2 == "192.168.1.6"

    async def test_untrusted_peer_ignores_xff(self, mock_app, fake_redis, monkeypatch):
        mw = RateLimitMiddleware(mock_app, redis_url="redis://localhost:6379/0", whitelist=[])
        result = await _peer_ip(mw, "198.51.100.7", "203.0.113.9", ["10.0.0.0/8"], monkeypatch)
        assert result == "198.51.100.7"
