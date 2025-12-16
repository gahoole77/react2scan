"""Infrastructure discovery providers."""

from react2scan.providers.base import BaseProvider
from react2scan.providers.cloudflare import CloudflareProvider

__all__ = ["BaseProvider", "CloudflareProvider"]

# Registry of available providers
PROVIDERS: dict[str, type[BaseProvider]] = {
    "cloudflare": CloudflareProvider,
}


def get_provider(name: str) -> type[BaseProvider] | None:
    """Get a provider class by name."""
    return PROVIDERS.get(name.lower())


def list_providers() -> list[str]:
    """List all available provider names."""
    return list(PROVIDERS.keys())
