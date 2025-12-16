"""Abstract base class for vulnerability scanners."""

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from datetime import datetime, timezone

from react2scan.constants import DEFAULT_THREADS, DEFAULT_TIMEOUT_SECONDS
from react2scan.models import InfrastructureMap, ScanReport, ScanResult


class BaseScanner(ABC):
    """
    Abstract base class for vulnerability scanners.

    Scanners are responsible for testing targets from an InfrastructureMap
    for specific vulnerabilities.

    Subclasses must implement the `scan_target` method for individual targets,
    and may override `scan` for custom batch scanning logic.
    """

    # Scanner identifier
    name: str = "base"

    # Human-readable description
    description: str = "Base scanner"

    # CVE identifiers if applicable
    cves: list[str] = []

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        threads: int = DEFAULT_THREADS,
        verify_ssl: bool = False,
    ) -> None:
        """
        Initialize the scanner.

        Args:
            timeout: Request timeout in seconds.
            threads: Maximum concurrent scan threads.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.timeout = timeout
        self.threads = threads
        self.verify_ssl = verify_ssl

    @abstractmethod
    async def scan_target(
        self,
        hostname: str,
        target_ip: str,
        **options: bool | str | int,
    ) -> ScanResult:
        """
        Scan a single target for vulnerabilities.

        Args:
            hostname: The hostname to use in Host header.
            target_ip: The IP address to connect to directly.
            **options: Scanner-specific options.

        Returns:
            ScanResult with vulnerability status.
        """

    @abstractmethod
    async def scan(
        self,
        infrastructure: InfrastructureMap,
        **options: bool | str | int,
    ) -> AsyncIterator[ScanResult]:
        """
        Scan all targets in an infrastructure map.

        Args:
            infrastructure: The infrastructure map to scan.
            **options: Scanner-specific options.

        Yields:
            ScanResult for each scanned target.
        """
        # Abstract async generators need a yield for type checking
        # This code is never executed - subclasses must override
        if False:  # pragma: no cover
            yield  # type: ignore[misc]

    async def create_report(
        self,
        infrastructure: InfrastructureMap,
        **options: bool | str | int,
    ) -> ScanReport:
        """
        Scan infrastructure and create a complete report.

        Args:
            infrastructure: The infrastructure map to scan.
            **options: Scanner-specific options.

        Returns:
            Complete ScanReport with all results.
        """
        report = ScanReport(
            infrastructure=infrastructure,
            scanner=self.name,
            started_at=datetime.now(timezone.utc),
            options={k: v for k, v in options.items()},
        )

        async for result in self.scan(infrastructure, **options):
            report.results.append(result)

        report.completed_at = datetime.now(timezone.utc)
        return report

    async def close(self) -> None:
        """Close any open connections. Override in subclasses if needed."""
        pass

    async def __aenter__(self) -> "BaseScanner":
        """Async context manager entry."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Async context manager exit."""
        await self.close()


class ScannerError(Exception):
    """Base exception for scanner errors."""

    def __init__(self, message: str, scanner: str = "unknown") -> None:
        self.scanner = scanner
        super().__init__(f"[{scanner}] {message}")
