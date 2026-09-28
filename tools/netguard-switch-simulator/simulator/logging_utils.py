from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from .config import logs_dir


def setup_logging() -> logging.Logger:
    logger = logging.getLogger("netguard_switch_simulator")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    handler = RotatingFileHandler(
        logs_dir() / "netguard_switch_simulator.log",
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger
