"""
Logging module for CloudSec-Copilot.
"""

import logging

from rich.logging import RichHandler


def setup_logger(name: str = "cloudsec", level: int = logging.INFO) -> logging.Logger:
    """Setup and return logger instance without duplicate handlers."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    for existing_handler in list(logger.handlers):
        logger.removeHandler(existing_handler)
        existing_handler.close()

    handler = RichHandler(rich_tracebacks=True, show_time=True, show_path=False)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


logger = setup_logger()
