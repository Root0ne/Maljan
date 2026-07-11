import logging
import sys


def setup_logger(name: str = "maljan", level: int = logging.INFO) -> logging.Logger:
    """Configures and returns a standardized logger."""
    logger = logging.getLogger(name)

    if not logger.handlers:
        logger.setLevel(level)

        # Create console handler with a clean format
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


def quiet_noisy_http_loggers() -> None:
    """Pin third-party HTTP-client loggers to WARNING.

    F17 (2026-07-05): the OpenAI / httpx / httpcore clients log full request
    bodies at DEBUG level. Running the app with ``DEBUG=true`` flips the root
    logger to DEBUG, which then dumps every analyst prompt — including the
    decompiled sample content — into the logs and floods them. These loggers
    stay at WARNING regardless of the application log level; genuine client
    errors still surface.
    """
    for _noisy in ("openai", "openai._base_client", "httpx", "httpcore"):
        logging.getLogger(_noisy).setLevel(logging.WARNING)


# Global application logger
logger = setup_logger()
base_logger = logger
quiet_noisy_http_loggers()
