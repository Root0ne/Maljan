"""Maljan API — Centralized logging configuration.

Provides structured logging with:
- JSON output for production (machine-parseable)
- Human-readable colored output for development
- Request/response middleware for API tracing
- Correlation IDs for request tracking
- Performance timing for all endpoints
"""

import logging
import sys
from contextvars import ContextVar
from typing import Any

from app.config import settings

# Context variable for request correlation ID
correlation_id: ContextVar[str] = ContextVar("correlation_id", default="-")


class StructuredFormatter(logging.Formatter):
    """JSON-structured log formatter for production environments."""

    def format(self, record: logging.LogRecord) -> str:
        import json
        from datetime import UTC, datetime

        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "correlation_id": correlation_id.get("-"),
        }

        # Add module/function info
        if record.pathname:
            log_entry["module"] = record.module
            log_entry["function"] = record.funcName
            log_entry["line"] = record.lineno

        # Add exception info if present
        if record.exc_info and record.exc_info[0] is not None:
            import traceback

            log_entry["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exception(*record.exc_info),
            }

        # Add extra fields
        for key in (
            "method",
            "url",
            "status_code",
            "duration_ms",
            "client_ip",
            "user_id",
            "job_id",
            "sample_id",
            "error_detail",
            "component",
        ):
            value = getattr(record, key, None)
            if value is not None:
                log_entry[key] = value

        return json.dumps(log_entry, default=str)


class HumanReadableFormatter(logging.Formatter):
    """Colored, human-readable formatter for development."""

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        corr_id = correlation_id.get("-")
        prefix = f"{color}{record.levelname:<8}{self.RESET}"
        timestamp = self.formatTime(record, "%Y-%m-%d %H:%M:%S")

        # Build the base message
        msg = f"{timestamp} {prefix} [{record.name}] [{corr_id[:8]}] {record.getMessage()}"

        # Append extra fields if present
        extras = []
        for key in (
            "method",
            "url",
            "status_code",
            "duration_ms",
            "client_ip",
            "user_id",
            "job_id",
        ):
            value = getattr(record, key, None)
            if value is not None:
                extras.append(f"{key}={value}")
        if extras:
            msg += f" | {' '.join(extras)}"

        # Append exception if present
        if record.exc_info and record.exc_info[0] is not None:
            msg += "\n" + self.formatException(record.exc_info)

        return msg


def setup_logging() -> None:
    """Configure application-wide logging.

    In production (debug=False): JSON structured output to stdout.
    In development (debug=True): Human-readable colored output to stderr.
    """
    root_logger = logging.getLogger()

    # Clear existing handlers to avoid duplicates on reload
    root_logger.handlers.clear()

    # Set base level
    log_level = logging.DEBUG if settings.debug else logging.INFO
    root_logger.setLevel(log_level)

    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)

    # Choose formatter based on environment
    if settings.debug:
        formatter = HumanReadableFormatter()
    else:
        formatter = StructuredFormatter()

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

    # Reduce noise from third-party libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if settings.debug else logging.WARNING
    )
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("arq").setLevel(logging.INFO)

    # Suppress known non-critical MCP stdio cancel-scope noise
    # (anyio/nest_asyncio incompatibility in mcp client cleanup)
    logging.getLogger("mcp.client.stdio").setLevel(logging.CRITICAL)

    # Log startup message
    logger = logging.getLogger("maljan.startup")
    logger.info(
        "Logging initialized",
        extra={"component": "logging", "level": record_level_name(log_level)},
    )


def record_level_name(level: int) -> str:
    """Convert logging level int to name."""
    return logging.getLevelName(level)


def get_logger(name: str) -> logging.Logger:
    """Get a named logger under the 'maljan' namespace.

    Usage:
        from app.logging_config import get_logger
        logger = get_logger(__name__)
        logger.info("Something happened", extra={"user_id": "abc"})
    """
    return logging.getLogger(f"maljan.{name}")
