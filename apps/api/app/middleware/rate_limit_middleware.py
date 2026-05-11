"""Rate limiting middleware using Redis sliding window counter.

Protects API endpoints from abuse by tracking per-IP request counts
in Redis with automatic TTL-based window expiration.

Headers added to every response:
    X-RateLimit-Limit:     Maximum requests allowed per window
    X-RateLimit-Remaining: Requests remaining in current window
    X-RateLimit-Reset:     Seconds until window resets

When limit is exceeded, returns 429 with Retry-After header.
"""

from __future__ import annotations

import redis.asyncio as aioredis
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.logging_config import get_logger

logger = get_logger("middleware.rate_limit")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware that limits requests per IP using Redis-backed counters.

    Uses a simple sliding window via Redis INCR + EXPIRE:
      - First request in window: create key with TTL = window_seconds
      - Subsequent requests: increment counter
      - When counter > max_requests: reject with 429
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        redis_url: str,
        enabled: bool = True,
        max_requests: int = 100,
        window_seconds: int = 60,
        whitelist: list[str] | None = None,
    ) -> None:
        super().__init__(app)
        self.enabled = enabled
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.whitelist = set(whitelist or [])
        self._redis_pool = aioredis.ConnectionPool.from_url(
            redis_url,
            max_connections=20,
        )

        # Lua script: atomic INCR + EXPIRE-on-first-hit. Returns [count, ttl].
        self._incr_script = (
            "local current = redis.call('INCR', KEYS[1]) "
            "if current == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end "
            "local ttl = redis.call('TTL', KEYS[1]) "
            "return {current, ttl}"
        )

    @staticmethod
    def _extract_client_ip(request: Request) -> str:
        """Return the client IP, honouring X-Forwarded-For from trusted proxies."""
        from app.config import settings

        trusted = set(getattr(settings, "trusted_proxy_ips", []) or [])
        peer = getattr(request.client, "host", "") or "unknown"
        if peer in trusted:
            xff = request.headers.get("x-forwarded-for", "")
            if xff:
                # The left-most XFF entry is the original client.
                return xff.split(",")[0].strip() or peer
        return peer

    async def _incr_with_ttl(
        self,
        redis: aioredis.Redis,
        key: str,
        window_seconds: int,
    ) -> tuple[int, int]:
        try:
            result = await redis.eval(self._incr_script, 1, key, window_seconds)
            return int(result[0]), int(result[1])
        except Exception as exc:
            logger.warning("Rate-limit Lua script failed (%s); failing open.", exc)
            return 0, window_seconds

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Check rate limit before processing request."""
        if not self.enabled:
            return await call_next(request)

        path = request.url.path
        if path in self.whitelist:
            return await call_next(request)

        client_ip = self._extract_client_ip(request)
        key = f"ratelimit:{client_ip}:{path}"

        redis = aioredis.Redis(connection_pool=self._redis_pool)
        try:
            # Atomic incr-with-TTL: SETNX-style via Lua. Avoids the previous
            # bug where two concurrent first-requests both saw ttl=-1, raced
            # on EXPIRE, and one of them ended up without a TTL at all.
            current_count, ttl_remaining = await self._incr_with_ttl(
                redis, key, self.window_seconds
            )

            remaining = max(0, self.max_requests - current_count)

            # Rate limit exceeded
            if current_count > self.max_requests:
                logger.warning(
                    "Rate limit exceeded for %s on %s (%d/%d)",
                    client_ip,
                    path,
                    current_count,
                    self.max_requests,
                    extra={
                        "client_ip": client_ip,
                        "path": path,
                        "limit": self.max_requests,
                        "count": current_count,
                    },
                )
                return Response(
                    content='{"detail":"Rate limit exceeded. Please try again later."}',
                    status_code=429,
                    media_type="application/json",
                    headers={
                        "Retry-After": str(ttl_remaining),
                        "X-RateLimit-Limit": str(self.max_requests),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(ttl_remaining),
                    },
                )

            # Proceed with request
            response = await call_next(request)
            response.headers["X-RateLimit-Limit"] = str(self.max_requests)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = str(ttl_remaining)
            return response

        except Exception as exc:
            # Graceful degradation: if Redis is unavailable, allow the request
            # but log the failure so operators are aware.
            logger.error(
                "Rate limit check failed for %s: %s",
                client_ip,
                exc,
                extra={"client_ip": client_ip, "path": path},
            )
            return await call_next(request)
