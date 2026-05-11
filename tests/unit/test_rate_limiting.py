"""Unit tests for the Redis-backed rate limiting middleware."""

from __future__ import annotations

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


class TestRateLimitMiddleware:
    """Tests for RateLimitMiddleware dispatch logic."""

    async def test_request_allowed_when_under_limit(self, mock_app, fake_redis):
        """Request proceeds normally when under the rate limit."""
        middleware = RateLimitMiddleware(
            mock_app,
            redis_url="redis://localhost:6379/0",
            enabled=True,
            max_requests=10,
            window_seconds=60,
            whitelist=[],
        )
        # Replace with fake Redis for testing
        middleware._redis_pool = fake_redis.connection_pool

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
            enabled=True,
            max_requests=2,
            window_seconds=60,
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
                "client": ("192.168.1.2", 12345),
            }
        )

        async def call_next(req):
            return Response(content='{"ok":true}', status_code=200)

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
            enabled=True,
            max_requests=1,
            window_seconds=60,
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
        for _ in range(5):
            response = await middleware.dispatch(request, call_next)
            assert response.status_code == 200

    async def test_disabled_middleware_allows_all(self, mock_app, fake_redis):
        """When disabled, all requests pass through without Redis checks."""
        middleware = RateLimitMiddleware(
            mock_app,
            redis_url="redis://localhost:6379/0",
            enabled=False,
            max_requests=1,
            window_seconds=60,
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
            enabled=True,
            max_requests=10,
            window_seconds=60,
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
        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 200

    async def test_different_ips_have_separate_counters(self, mock_app, fake_redis):
        """Each IP address has its own independent rate limit counter."""
        middleware = RateLimitMiddleware(
            mock_app,
            redis_url="redis://localhost:6379/0",
            enabled=True,
            max_requests=2,
            window_seconds=60,
            whitelist=[],
        )
        middleware._redis_pool = fake_redis.connection_pool

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

        allowed = await middleware.dispatch(req_b, call_next)
        assert allowed.status_code == 200
