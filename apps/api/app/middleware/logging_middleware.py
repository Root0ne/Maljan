"""Maljan API — Logging middleware for request/response tracking.

Provides:
- Automatic correlation ID generation and propagation
- Request/response timing
- Error logging with full stack traces
- Slow request detection
"""

import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.logging_config import correlation_id, get_logger

logger = get_logger("middleware.http")

# Requests taking longer than this are flagged
SLOW_REQUEST_THRESHOLD_MS = 5000


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs every HTTP request and response with timing."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Generate and set correlation ID
        req_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        token = correlation_id.set(req_id)

        # Extract client info
        client_ip = request.client.host if request.client else "unknown"
        method = request.method
        url = str(request.url.path)

        # Log request start
        logger.info(
            f"Request started: {method} {url}",
            extra={
                "method": method,
                "url": url,
                "client_ip": client_ip,
                "component": "http",
            },
        )

        # Process request with timing
        start_time = time.perf_counter()
        status_code = 500  # Default in case of unhandled error

        try:
            response = await call_next(request)
            status_code = response.status_code

            # Add correlation ID to response headers
            response.headers["X-Request-ID"] = req_id

            return response

        except Exception as exc:
            logger.error(
                f"Unhandled exception during {method} {url}: {exc}",
                exc_info=True,
                extra={
                    "method": method,
                    "url": url,
                    "client_ip": client_ip,
                    "status_code": 500,
                    "error_detail": str(exc),
                    "component": "http",
                },
            )
            raise

        finally:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # Choose log level based on status code and duration
            log_extra = {
                "method": method,
                "url": url,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "client_ip": client_ip,
                "component": "http",
            }

            if status_code >= 500:
                logger.error(
                    f"Response: {method} {url} -> {status_code} ({duration_ms}ms)",
                    extra=log_extra,
                )
            elif status_code >= 400:
                logger.warning(
                    f"Response: {method} {url} -> {status_code} ({duration_ms}ms)",
                    extra=log_extra,
                )
            elif duration_ms > SLOW_REQUEST_THRESHOLD_MS:
                logger.warning(
                    f"SLOW Response: {method} {url} -> {status_code} ({duration_ms}ms)",
                    extra=log_extra,
                )
            else:
                logger.info(
                    f"Response: {method} {url} -> {status_code} ({duration_ms}ms)",
                    extra=log_extra,
                )

            # Reset correlation ID
            correlation_id.reset(token)
