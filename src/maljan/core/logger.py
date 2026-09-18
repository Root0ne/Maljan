import logging
import sys

# The handler this module installs, by name, so it can be told apart from one
# a host added and taken away again when somebody else starts formatting.
_OWN_HANDLER = "maljan.default"


def setup_logger(name: str = "maljan", level: int = logging.INFO) -> logging.Logger:
    """Configures and returns a standardized logger.

    The handler exists for the caller who has none — a CLI run, a script, a
    test. A host that formats logs itself installs a handler on the root
    logger, these records propagate to it, and then every line is written
    twice: once plain by this handler and once by the root's. Such a host
    calls ``hand_over_to_root`` and this handler steps aside.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        logger.setLevel(level)

        # Create console handler with a clean format
        handler = logging.StreamHandler(sys.stdout)
        handler.set_name(_OWN_HANDLER)
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


def hand_over_to_root(name: str = "maljan") -> bool:
    """Drop this module's handler, leaving the root's to format these lines.

    Called by a host that has just installed a root handler of its own. Says
    whether there was one to drop, and takes away only the handler this module
    installed: a caller that added its own keeps it.

    Propagation stays on rather than being switched off in its place. These
    records have to reach the root handler — that handler is the structured
    one in production, and it is also what a test's capture is attached to —
    so the duplicate is removed by taking away the second writer, not by
    cutting the line off from the first.
    """
    logger = logging.getLogger(name)
    dropped = False
    for handler in list(logger.handlers):
        if handler.get_name() == _OWN_HANDLER:
            logger.removeHandler(handler)
            handler.close()
            dropped = True
    logger.propagate = True
    return dropped


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
quiet_noisy_http_loggers()
