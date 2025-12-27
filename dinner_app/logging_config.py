"""Logging configuration for the dinner app."""

from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path


def get_log_dir() -> Path:
    """Get the log directory path."""
    if os.name == 'nt':
        base = Path(os.environ.get('LOCALAPPDATA', Path.home()))
        log_dir = base / 'WhatsForDinner' / 'logs'
    else:
        xdg_data = os.environ.get('XDG_DATA_HOME', Path.home() / '.local' / 'share')
        log_dir = Path(xdg_data) / 'WhatsForDinner' / 'logs'

    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def setup_logging(debug: bool = False) -> logging.Logger:
    """
    Configure application logging.

    Args:
        debug: Enable debug level logging

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger('dinner_app')
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    # Log format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # File handler with rotation (max 1MB, keep 3 backups)
    log_dir = get_log_dir()
    log_file = log_dir / 'dinner_app.log'

    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=1024 * 1024,  # 1 MB
        backupCount=3,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG if debug else logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Console handler for errors only (avoid cluttering GUI)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


def get_logger(name: str = 'dinner_app') -> logging.Logger:
    """Get a logger instance."""
    return logging.getLogger(name)
