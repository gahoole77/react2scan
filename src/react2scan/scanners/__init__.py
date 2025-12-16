"""Vulnerability scanners."""

from react2scan.scanners.base import BaseScanner, ScannerError
from react2scan.scanners.react2shell import React2ShellScanner

__all__ = ["BaseScanner", "ScannerError", "React2ShellScanner"]

# Registry of available scanners
SCANNERS: dict[str, type[BaseScanner]] = {
    "react2shell": React2ShellScanner,
}


def get_scanner(name: str) -> type[BaseScanner] | None:
    """Get a scanner class by name."""
    return SCANNERS.get(name.lower())


def list_scanners() -> list[str]:
    """List all available scanner names."""
    return list(SCANNERS.keys())
