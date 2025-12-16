"""Logging configuration for react2scan."""

import logging
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler


def configure_logging(
    level: int = logging.INFO,
    log_file: str | None = None,
    console: Console | None = None,
) -> None:
    """
    Configure logging for react2scan.

    Uses Rich for console output to properly integrate with progress bars
    and other Rich components.

    Args:
        level: Logging level (e.g., logging.DEBUG, logging.INFO).
        log_file: Optional file path to write logs to.
        console: Optional Rich console to use for logging output.
    """
    # Get root logger for react2scan
    root_logger = logging.getLogger("react2scan")
    root_logger.setLevel(level)

    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()

    # Rich console handler - writes to stderr to avoid breaking progress bars
    log_console = console or Console(stderr=True, force_terminal=True)
    rich_handler = RichHandler(
        console=log_console,
        show_time=True,
        show_path=False,
        markup=False,
        rich_tracebacks=True,
    )
    rich_handler.setLevel(level)
    root_logger.addHandler(rich_handler)

    # File handler (optional) - uses standard formatting
    if log_file:
        file_path = Path(log_file)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(file_path)
        file_handler.setLevel(level)
        file_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        root_logger.addHandler(file_handler)

    # Suppress verbose logging from dependencies
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("cloudflare").setLevel(logging.WARNING)
