"""Data models for infrastructure mapping and vulnerability scanning."""

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field


class RecordType(str, Enum):
    """DNS record types supported for scanning."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"


class VulnerabilityStatus(str, Enum):
    """Vulnerability scan result status."""

    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    ERROR = "error"
    SKIPPED = "skipped"


class DNSRecord(BaseModel):
    """A DNS record with its associated metadata for scanning."""

    name: str = Field(description="Full hostname (e.g., subdomain.example.com)")
    record_type: RecordType = Field(description="DNS record type (A, AAAA, CNAME)")
    content: str = Field(description="Record value (IP address or CNAME target)")
    proxied: bool = Field(default=False, description="Whether traffic is proxied through CDN")
    ttl: int | None = Field(default=None, description="TTL in seconds")

    @property
    def is_scannable(self) -> bool:
        """Check if this record can be scanned."""
        return self.record_type in (RecordType.A, RecordType.AAAA, RecordType.CNAME)


class Domain(BaseModel):
    """A domain (zone) with its DNS records."""

    name: str = Field(description="Domain name (e.g., example.com)")
    zone_id: str = Field(description="Provider-specific zone identifier")
    records: list[DNSRecord] = Field(default_factory=list, description="DNS records for this zone")
    account_id: str | None = Field(default=None, description="Provider account identifier")

    @property
    def scannable_records(self) -> list[DNSRecord]:
        """Get records that can be scanned (A, AAAA, CNAME)."""
        return [r for r in self.records if r.is_scannable]

    @property
    def record_count(self) -> int:
        """Total number of DNS records."""
        return len(self.records)


class InfrastructureMap(BaseModel):
    """Complete infrastructure map from a provider."""

    provider: str = Field(description="Provider identifier (e.g., 'cloudflare', 'route53')")
    domains: list[Domain] = Field(default_factory=list, description="Discovered domains")
    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of discovery",
    )
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description="Additional provider-specific metadata",
    )

    @property
    def total_records(self) -> int:
        """Total number of DNS records across all domains."""
        return sum(d.record_count for d in self.domains)

    @property
    def total_scannable(self) -> int:
        """Total number of scannable records (A, AAAA, CNAME)."""
        return sum(len(d.scannable_records) for d in self.domains)

    def get_all_targets(self, dedupe: bool = True) -> list[tuple[Domain, DNSRecord]]:
        """
        Get all scannable targets as (domain, record) pairs.

        Args:
            dedupe: If True, deduplicate by hostname to avoid scanning
                   the same endpoint multiple times.
        """
        targets = []
        seen: set[str] = set()

        for domain in self.domains:
            for record in domain.scannable_records:
                if dedupe and record.name in seen:
                    continue
                seen.add(record.name)
                targets.append((domain, record))

        return targets


class WAFStatus(BaseModel):
    """WAF protection status for a zone."""

    zone_id: str = Field(description="Cloudflare zone ID")
    zone_name: str = Field(description="Domain name")
    managed_ruleset_enabled: bool = Field(
        default=False,
        description="Whether Cloudflare Managed Ruleset is enabled",
    )
    error: str | None = Field(
        default=None,
        description="Error message if WAF status check failed",
    )


class ScanResult(BaseModel):
    """Result of scanning a single target."""

    hostname: str = Field(description="Target hostname that was scanned")
    target_ip: str | None = Field(
        default=None,
        description="IP address that was scanned (None if scanned via hostname)",
    )
    status: VulnerabilityStatus = Field(description="Scan result status")
    vulnerable: bool = Field(default=False, description="Whether the target is vulnerable")
    details: str | None = Field(default=None, description="Additional details or error message")
    response_snippet: str | None = Field(default=None, description="Relevant response excerpt")
    tested_path: str | None = Field(default=None, description="Path that was tested")
    waf_status: WAFStatus | None = Field(
        default=None,
        description="WAF protection status for this target's zone",
    )


class ScanReport(BaseModel):
    """Complete scan report for an infrastructure map."""

    infrastructure: InfrastructureMap = Field(description="Source infrastructure")
    results: list[ScanResult] = Field(default_factory=list, description="Individual scan results")
    scanner: str = Field(description="Scanner identifier")
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Scan start time",
    )
    completed_at: datetime | None = Field(default=None, description="Scan completion time")
    options: dict[str, Annotated[str | int | bool, Field()]] = Field(
        default_factory=dict,
        description="Scanner options used",
    )

    @property
    def vulnerable_count(self) -> int:
        """Count of vulnerable targets."""
        return sum(1 for r in self.results if r.vulnerable)

    @property
    def error_count(self) -> int:
        """Count of scan errors."""
        return sum(1 for r in self.results if r.status == VulnerabilityStatus.ERROR)

    @property
    def scanned_count(self) -> int:
        """Total targets scanned (excluding skipped)."""
        return sum(1 for r in self.results if r.status != VulnerabilityStatus.SKIPPED)
