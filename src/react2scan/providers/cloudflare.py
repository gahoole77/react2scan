"""Cloudflare infrastructure discovery provider."""

import asyncio
import logging
from datetime import datetime, timezone

import cloudflare
from cloudflare import AsyncCloudflare

from react2scan.constants import (
    CLOUDFLARE_AUTOMATIC_TTL,
    CLOUDFLARE_MANAGED_RULESET_ID,
    MAX_CONCURRENT_API_REQUESTS,
    SCANNABLE_RECORD_TYPES,
)
from react2scan.models import DNSRecord, Domain, InfrastructureMap, RecordType, WAFStatus
from react2scan.providers.base import (
    AuthenticationError,
    BaseProvider,
    ProviderError,
    RateLimitError,
)

logger = logging.getLogger(__name__)


class CloudflareProvider(BaseProvider):
    """
    Cloudflare infrastructure discovery provider.

    Discovers all zones (domains) and their DNS records from a Cloudflare account.
    Supports both API tokens and API keys for authentication.

    The provider captures:
    - Zone names and IDs
    - DNS records (A, AAAA, CNAME)
    - Proxy status (whether traffic goes through Cloudflare CDN)

    Also provides WAF status checking for zones to determine if the
    Cloudflare Managed Ruleset is enabled.
    """

    name = "cloudflare"
    description = "Cloudflare DNS and zone discovery"

    def __init__(
        self,
        api_token: str | None = None,
        api_key: str | None = None,
        api_email: str | None = None,
    ) -> None:
        """
        Initialize the Cloudflare provider.

        Args:
            api_token: Cloudflare API token (recommended).
            api_key: Cloudflare API key (legacy, requires api_email).
            api_email: Email associated with the API key.

        Raises:
            ValueError: If neither api_token nor api_key+api_email is provided.
        """
        if not api_token and not (api_key and api_email):
            raise ValueError("Either api_token or both api_key and api_email must be provided")

        self._client = AsyncCloudflare(
            api_token=api_token,
            api_key=api_key,
            api_email=api_email,
        )
        self._api_token = api_token
        self._api_key = api_key
        self._api_email = api_email

    async def close(self) -> None:
        """Close the Cloudflare client."""
        await self._client.close()

    async def validate_credentials(self) -> bool:
        """
        Validate Cloudflare credentials by attempting to list zones.

        Returns:
            True if credentials are valid.

        Raises:
            AuthenticationError: If credentials are invalid.
        """
        try:
            # Try to list zones with a limit of 1 to minimize API usage
            async for _ in self._client.zones.list(per_page=1):
                break
            return True
        except cloudflare.AuthenticationError as e:
            raise AuthenticationError(str(e), provider=self.name) from e
        except Exception as e:
            raise ProviderError(f"Failed to validate credentials: {e}", provider=self.name) from e

    async def discover(self) -> InfrastructureMap:
        """
        Discover all zones and DNS records from Cloudflare.

        Returns:
            InfrastructureMap containing all discovered domains and records.

        Raises:
            AuthenticationError: If authentication fails.
            RateLimitError: If rate limit is exceeded.
            ProviderError: For other API errors.
        """
        try:
            domains = await self._discover_zones()

            return InfrastructureMap(
                provider=self.name,
                domains=domains,
                discovered_at=datetime.now(timezone.utc),
                metadata={
                    "auth_method": "api_token" if self._api_token else "api_key",
                },
            )
        except cloudflare.AuthenticationError as e:
            raise AuthenticationError(str(e), provider=self.name) from e
        except cloudflare.RateLimitError as e:
            raise RateLimitError(str(e), provider=self.name) from e
        except ProviderError:
            raise
        except Exception as e:
            raise ProviderError(f"Discovery failed: {e}", provider=self.name) from e

    async def _discover_zones(self) -> list[Domain]:
        """Discover all zones and their DNS records."""
        # Collect all zones first
        logger.debug("Fetching zones from Cloudflare...")
        zones_data: list[tuple[str, str, str | None]] = []
        async for zone in self._client.zones.list():
            zones_data.append((zone.id, zone.name, getattr(zone.account, "id", None)))
        logger.debug(f"Found {len(zones_data)} zones")

        # Fetch DNS records for all zones concurrently
        # Use semaphore to limit concurrent requests and avoid rate limiting
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_API_REQUESTS)

        async def fetch_zone_records(
            zone_id: str, zone_name: str, account_id: str | None
        ) -> Domain:
            async with semaphore:
                records = await self._fetch_dns_records(zone_id)
                return Domain(
                    name=zone_name,
                    zone_id=zone_id,
                    records=records,
                    account_id=account_id,
                )

        tasks = [
            fetch_zone_records(zone_id, zone_name, account_id)
            for zone_id, zone_name, account_id in zones_data
        ]

        domains = await asyncio.gather(*tasks)
        return list(domains)

    async def _fetch_dns_records(self, zone_id: str) -> list[DNSRecord]:
        """
        Fetch DNS records for a specific zone.

        Args:
            zone_id: The Cloudflare zone ID.

        Returns:
            List of DNSRecord objects for scannable record types.
        """
        records: list[DNSRecord] = []

        async for record in self._client.dns.records.list(zone_id=zone_id):
            if record.type not in SCANNABLE_RECORD_TYPES:
                continue

            try:
                record_type = RecordType(record.type)
            except ValueError:
                continue

            proxied = getattr(record, "proxied", False) or False
            ttl = record.ttl if record.ttl != CLOUDFLARE_AUTOMATIC_TTL else None

            records.append(
                DNSRecord(
                    name=record.name,
                    record_type=record_type,
                    content=record.content,
                    proxied=proxied,
                    ttl=ttl,
                )
            )

        return records

    def _is_managed_ruleset_enabled(self, entrypoint: object) -> bool:
        """
        Check if the Cloudflare Managed Ruleset is enabled in a phase entrypoint.

        Args:
            entrypoint: The ruleset phase entrypoint response.

        Returns:
            True if the managed ruleset is deployed and enabled.
        """
        rules = getattr(entrypoint, "rules", None)
        if not rules:
            return False

        for rule in rules:
            action = getattr(rule, "action", None)
            if action != "execute":
                continue

            params = getattr(rule, "action_parameters", None)
            ruleset_id = getattr(params, "id", None) if params else None
            if ruleset_id != CLOUDFLARE_MANAGED_RULESET_ID:
                continue

            # Found the managed ruleset - check if enabled (defaults to True)
            return getattr(rule, "enabled", True)

        return False

    async def get_waf_status(self, zone_id: str, zone_name: str) -> WAFStatus:
        """
        Check WAF managed ruleset status for a zone.

        Args:
            zone_id: The Cloudflare zone ID.
            zone_name: The domain name (for reporting).

        Returns:
            WAFStatus with ruleset enablement information.
        """
        try:
            entrypoint = await self._client.rulesets.phases.get(
                ruleset_phase="http_request_firewall_managed",
                zone_id=zone_id,
            )
            is_enabled = self._is_managed_ruleset_enabled(entrypoint)
            status_str = "enabled" if is_enabled else "disabled"
            logger.debug(f"Zone {zone_name}: Managed Ruleset {status_str}")

            return WAFStatus(
                zone_id=zone_id,
                zone_name=zone_name,
                managed_ruleset_enabled=is_enabled,
            )

        except cloudflare.NotFoundError:
            logger.debug(f"Zone {zone_name}: No WAF managed rules configured")
            return WAFStatus(
                zone_id=zone_id,
                zone_name=zone_name,
                managed_ruleset_enabled=False,
            )

        except cloudflare.APIError as e:
            logger.debug(f"Zone {zone_name}: WAF check failed - {e}")
            return WAFStatus(
                zone_id=zone_id,
                zone_name=zone_name,
                managed_ruleset_enabled=False,
                error=f"API error: {e}",
            )

        except Exception as e:
            logger.debug(f"Zone {zone_name}: WAF check failed - {e}")
            return WAFStatus(
                zone_id=zone_id,
                zone_name=zone_name,
                managed_ruleset_enabled=False,
                error=str(e),
            )

    async def get_waf_status_batch(
        self, zones: list[tuple[str, str]]
    ) -> dict[str, WAFStatus]:
        """
        Check WAF status for multiple zones concurrently.

        Args:
            zones: List of (zone_id, zone_name) tuples.

        Returns:
            Dict mapping zone_id to WAFStatus.
        """
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_API_REQUESTS)

        async def check_with_semaphore(zone_id: str, zone_name: str) -> tuple[str, WAFStatus]:
            async with semaphore:
                status = await self.get_waf_status(zone_id, zone_name)
                return zone_id, status

        tasks = [check_with_semaphore(zid, zname) for zid, zname in zones]
        results = await asyncio.gather(*tasks)

        return {zone_id: status for zone_id, status in results}
