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


# Global application logger
logger = setup_logger()
base_logger = logger
