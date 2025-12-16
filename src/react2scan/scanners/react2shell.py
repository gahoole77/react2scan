"""
React2Shell Scanner - Detects RSC/Next.js vulnerabilities.

CVE-2025-55182

Detection logic (payload & patterns) based on research by Assetnote Security Research Team.
Original: https://github.com/assetnote/react2shell-scanner

Everything else is original:
- Async scanning with httpx
- Auto HTTPS/HTTP fallback
- Infrastructure integration
"""

import asyncio
import logging
from collections.abc import AsyncIterator

import httpx

from react2scan.constants import (
    DEFAULT_SCAN_PATHS,
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT_SECONDS,
    MULTIPART_BOUNDARY,
    NEXTJS_ACCEPT_HEADER,
    NEXTJS_ACTION_HEADER,
    NEXTJS_ROUTER_STATE_TREE,
    RESPONSE_SNIPPET_MAX_LENGTH,
    SAFE_CHECK_ERROR_DIGEST,
    SAFE_CHECK_PATTERNS,
    SAFE_CHECK_REDIRECT_INDICATORS,
    USER_AGENT,
)
from react2scan.models import InfrastructureMap, ScanResult, VulnerabilityStatus
from react2scan.scanners.base import BaseScanner

logger = logging.getLogger(__name__)

# Retry configuration
DEFAULT_MAX_RETRIES = 2


class React2ShellScanner(BaseScanner):
    """
    Scanner for React Server Components (RSC) / Next.js vulnerabilities.

    Based on Assetnote's react2shell-scanner.
    Detects CVE-2025-55182.

    Uses safe side-channel detection (from Assetnote's research):
    - Sends a malformed RSC payload that triggers parsing errors
    - Detects vulnerability via error message patterns
    - No code is executed on the target server

    The non-RCE detection payload is not blocked by Cloudflare WAF, so
    scanning through the CDN works reliably.
    """

    name = "react2shell"
    description = "React Server Components / Next.js Scanner"
    cves = ["CVE-2025-55182"]

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        threads: int = DEFAULT_THREADS,
        verify_ssl: bool = False,
        paths: list[str] | None = None,
    ) -> None:
        """
        Initialize the React2Shell scanner.

        Args:
            timeout: Request timeout in seconds.
            threads: Maximum concurrent scan threads.
            verify_ssl: Whether to verify SSL certificates.
            paths: Custom paths to test.
        """
        super().__init__(timeout=timeout, threads=threads, verify_ssl=verify_ssl)
        self.paths = paths or DEFAULT_SCAN_PATHS
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                verify=self.verify_ssl,
                follow_redirects=False,
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _build_payload(self) -> tuple[str, str]:
        """
        Build safe multipart payload for side-channel detection.

        This payload triggers RSC parsing errors that reveal vulnerability
        without executing any code on the target.
        """
        body = (
            f"--{MULTIPART_BOUNDARY}\r\n"
            'Content-Disposition: form-data; name="1"\r\n\r\n'
            "{}\r\n"
            f"--{MULTIPART_BOUNDARY}\r\n"
            'Content-Disposition: form-data; name="0"\r\n\r\n'
            '["$1:aa:aa"]\r\n'
            f"--{MULTIPART_BOUNDARY}--"
        )

        content_type = f"multipart/form-data; boundary={MULTIPART_BOUNDARY}"
        return body, content_type

    def _check_vulnerable_response(self, response: httpx.Response) -> tuple[bool, str | None]:
        """
        Check if response indicates vulnerability.

        Looks for specific RSC parsing error patterns that indicate
        the target is vulnerable to deserialization attacks.

        Args:
            response: HTTP response to analyze.

        Returns:
            Tuple of (is_vulnerable, response_snippet).
        """
        text = response.text
        status = response.status_code

        # Primary check: 500 status with RSC error digest (Assetnote's method)
        if status == 500 and SAFE_CHECK_ERROR_DIGEST in text:
            return True, text[:RESPONSE_SNIPPET_MAX_LENGTH]

        # Secondary: Look for specific RSC parsing errors
        for pattern in SAFE_CHECK_PATTERNS:
            if pattern in text:
                return True, text[:RESPONSE_SNIPPET_MAX_LENGTH]

        # Check for redirect indicators
        redirect_keyword, digest_keyword = SAFE_CHECK_REDIRECT_INDICATORS
        if redirect_keyword in text and digest_keyword in text.lower():
            return True, text[:RESPONSE_SNIPPET_MAX_LENGTH]

        return False, None

    async def _try_request(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        body: bytes,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> httpx.Response | None:
        """Try a single request with retry logic for transient failures.

        Args:
            client: The HTTP client to use.
            url: The URL to request.
            headers: Request headers.
            body: Request body.
            max_retries: Maximum number of retry attempts.

        Returns:
            Response if successful, None if all attempts failed due to connection issues.
        """
        last_error: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                return await client.post(url, content=body, headers=headers)
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                last_error = e

        # Only log if all retries failed
        if last_error:
            logger.debug(f"Connection failed for {url}: {last_error}")
        return None

    async def scan_target(
        self,
        hostname: str,
        target: str | None = None,
        **options: bool | str | int,
    ) -> ScanResult:
        """
        Scan a single target for React2Shell vulnerability.

        Tries HTTPS first, falls back to HTTP if connection fails.

        Args:
            hostname: The hostname to scan.
            target: Optional IP address for direct connection (CDN bypass).
                   If None, scans via hostname (through CDN).
            **options: Additional options (unused, for interface compatibility).

        Returns:
            ScanResult with vulnerability status.
        """
        # Use hostname for URL if no direct target IP provided
        url_host = target or hostname
        body, content_type = self._build_payload()
        client = await self._get_client()

        headers = {
            "Host": hostname,
            "Content-Type": content_type,
            "Accept": NEXTJS_ACCEPT_HEADER,
            "Next-Action": NEXTJS_ACTION_HEADER,
            "Next-Router-State-Tree": NEXTJS_ROUTER_STATE_TREE,
            "User-Agent": USER_AGENT,
        }

        for path in self.paths:
            for scheme in ("https", "http"):
                url = f"{scheme}://{url_host}{path}"

                try:
                    response = await self._try_request(client, url, headers, body.encode())

                    if response is None:
                        continue

                    is_vulnerable, snippet = self._check_vulnerable_response(response)

                    if is_vulnerable:
                        logger.info(f"VULNERABLE: {hostname} on {path}")
                        return ScanResult(
                            hostname=hostname,
                            target_ip=target,
                            status=VulnerabilityStatus.VULNERABLE,
                            vulnerable=True,
                            details=f"Vulnerable to {', '.join(self.cves)}",
                            response_snippet=snippet,
                            tested_path=path,
                        )

                    break

                except (httpx.HTTPError, httpx.InvalidURL) as e:
                    return ScanResult(
                        hostname=hostname,
                        target_ip=target,
                        status=VulnerabilityStatus.ERROR,
                        vulnerable=False,
                        details=f"HTTP error: {e}",
                        tested_path=path,
                    )

        return ScanResult(
            hostname=hostname,
            target_ip=target,
            status=VulnerabilityStatus.NOT_VULNERABLE,
            vulnerable=False,
            details="No vulnerability detected",
            tested_path=",".join(self.paths),
        )

    async def scan(
        self,
        infrastructure: InfrastructureMap,
        **options: bool | str | int,
    ) -> AsyncIterator[ScanResult]:
        """
        Scan all targets in an infrastructure map.

        Scans each hostname directly through the CDN (e.g., Cloudflare).
        The detection payload is safe and not blocked by WAF rules.

        Args:
            infrastructure: The infrastructure map to scan.
            **options: Scanner options (unused).

        Yields:
            ScanResult for each scanned target.
        """
        targets = infrastructure.get_all_targets()
        if not targets:
            return

        semaphore = asyncio.Semaphore(self.threads)

        async def scan_with_semaphore(hostname: str) -> ScanResult:
            async with semaphore:
                return await self.scan_target(hostname, **options)

        tasks = [scan_with_semaphore(record.name) for _domain, record in targets]

        for coro in asyncio.as_completed(tasks):
            yield await coro
