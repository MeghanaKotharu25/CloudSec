"""
Logging module for CloudSec-Copilot.
"""

import logging
import sys
from rich.logging import RichHandler

def setup_logger(name: str = "cloudsec", level: int = logging.INFO) -> logging.Logger:
    """Setup and return logger instance."""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    if not logger.handlers:
        handler = RichHandler(rich_tracebacks=True, show_time=True, show_path=False)
        formatter = logging.Formatter("%(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
    return logger

logger = setup_logger()
