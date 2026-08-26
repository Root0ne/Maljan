"""Standard security response headers (audit 2026-05-19 SEC-CORS-HEADERS-01).

The 2026-05-17 audit added CORS but not the rest of the common defensive
header set. This middleware adds the recommended baseline on every
response. None of these headers are sensitive to API behaviour — they
exist purely to harden browser-side handling of stray or hostile content.

References:
    - https://owasp.org/www-project-secure-headers/
    - https://web.dev/articles/security-headers
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# A minimal CSP that allows the API to serve its own resources and the
# Swagger UI assets it bundles, while disallowing everything else. The
# frontend is a separate origin so it never inherits this policy.
_DEFAULT_CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add a curated set of security response headers to every response.

    Operators can override per-header values via constructor arguments; the
    defaults are appropriate for the API server which is consumed by the
    Maljan SPA only.
    """

    def __init__(
        self,
        app: object,
        *,
        content_security_policy: str | None = _DEFAULT_CSP,
        enable_hsts: bool = False,
    ) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self._csp = content_security_policy
        # HSTS only makes sense when the server actually terminates TLS.
        # Local dev (HTTP) should leave it off so browsers don't pin the
        # plain-text endpoint by accident.
        self._hsts = enable_hsts

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        # Use setdefault so an explicit header set by a handler always wins.
        headers = response.headers
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()",
        )
        if self._csp:
            headers.setdefault("Content-Security-Policy", self._csp)
        if self._hsts:
            headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response
