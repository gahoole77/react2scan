"""Abstract base class for infrastructure providers."""

from abc import ABC, abstractmethod
from types import TracebackType

from react2scan.models import InfrastructureMap


class BaseProvider(ABC):
    """
    Abstract base class for infrastructure discovery providers.

    Providers are responsible for connecting to cloud platforms (Cloudflare, AWS, etc.)
    and discovering domains, subdomains, and their associated DNS records.

    Subclasses must implement the `discover` method to return an InfrastructureMap.
    """

    # Provider identifier (e.g., "cloudflare", "route53")
    name: str = "base"

    # Human-readable description
    description: str = "Base provider"

    @abstractmethod
    async def discover(self) -> InfrastructureMap:
        """
        Discover all domains and DNS records from this provider.

        Returns:
            InfrastructureMap containing all discovered domains and records.

        Raises:
            ProviderError: If discovery fails due to authentication or API errors.
        """
        pass

    @abstractmethod
    async def validate_credentials(self) -> bool:
        """
        Validate that the provider credentials are valid.

        Returns:
            True if credentials are valid, False otherwise.
        """
        pass

    async def __aenter__(self) -> "BaseProvider":
        """Async context manager entry."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Async context manager exit - cleanup resources."""
        await self.close()

    async def close(self) -> None:
        """Close any open connections. Override in subclasses if needed."""
        pass


class ProviderError(Exception):
    """Base exception for provider errors."""

    def __init__(self, message: str, provider: str = "unknown") -> None:
        self.provider = provider
        super().__init__(f"[{provider}] {message}")


class AuthenticationError(ProviderError):
    """Raised when provider authentication fails."""

    pass


class RateLimitError(ProviderError):
    """Raised when provider rate limit is exceeded."""

    def __init__(self, message: str, provider: str = "unknown", retry_after: int | None = None):
        self.retry_after = retry_after
        super().__init__(message, provider)
