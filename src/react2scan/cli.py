"""Command-line interface for react2scan."""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.panel import Panel

from react2scan import __version__
from react2scan.constants import (
    DEFAULT_THREADS,
    DEFAULT_TIMEOUT_SECONDS,
)
from react2scan.logger import configure_logging
from react2scan.models import InfrastructureMap, ScanReport, ScanResult
from react2scan.output import Console
from react2scan.providers import PROVIDERS, get_provider, list_providers
from react2scan.providers.cloudflare import CloudflareProvider
from react2scan.scanners import SCANNERS, list_scanners
from react2scan.scanners.react2shell import React2ShellScanner

logger = logging.getLogger(__name__)


def _validate_paths(paths: str) -> list[str]:
    """Validate and parse comma-separated paths.

    Args:
        paths: Comma-separated path string (e.g., "/,/api,/admin")

    Returns:
        List of validated paths.

    Raises:
        typer.BadParameter: If any path is invalid.
    """
    validated = []
    for p in paths.split(","):
        p = p.strip()
        if not p:
            continue
        if not p.startswith("/"):
            raise typer.BadParameter(f"Path must start with '/': {p}")
        validated.append(p)
    if not validated:
        raise typer.BadParameter("At least one valid path is required")
    return validated


def _validate_cloudflare_credentials(
    console: Console,
    api_token: str | None,
    api_key: str | None,
    api_email: str | None,
) -> None:
    """Validate Cloudflare credentials and exit with helpful message if missing.

    Args:
        console: Console instance for output.
        api_token: Cloudflare API token.
        api_key: Cloudflare API key (legacy).
        api_email: Email for API key auth.

    Raises:
        typer.Exit: If credentials are missing.
    """
    if api_token or (api_key and api_email):
        return

    console.print_error("Missing Cloudflare API token")
    console.console.print()
    console.console.print("[bold]How to fix:[/]")
    console.console.print()
    console.console.print("  Option 1: Set environment variable")
    console.console.print("    [dim]export CLOUDFLARE_API_TOKEN='your-token'[/]")
    console.console.print()
    console.console.print("  Option 2: Pass it directly")
    console.console.print("    [dim]react2scan scan cloudflare -t 'your-token'[/]")
    console.console.print()
    console.console.print(
        "  [dim]Get a token at: https://dash.cloudflare.com/profile/api-tokens[/]"
    )
    console.console.print("  [dim]Required permissions: Zone:Read, DNS:Read[/]")
    raise typer.Exit(1)


def _print_banner_and_help(ctx: typer.Context) -> None:
    """Print banner followed by help text."""
    console = Console()
    console.print_banner()
    console.console.print(ctx.get_help())
    raise typer.Exit()


async def _enrich_with_waf_status(
    results: list[ScanResult],
    hostname_to_zone: dict[str, tuple[str, str]],
    api_token: str | None,
    api_key: str | None,
    api_email: str | None,
) -> None:
    """
    Enrich scan results with WAF status from Cloudflare.

    Args:
        results: List of vulnerable scan results to enrich.
        hostname_to_zone: Mapping of hostname to (zone_id, zone_name).
        api_token: Cloudflare API token.
        api_key: Cloudflare API key (legacy).
        api_email: Email for API key auth.
    """
    # Collect unique zones
    zones_to_check = {
        zone_id: zone_name
        for result in results
        if (zone := hostname_to_zone.get(result.hostname))
        for zone_id, zone_name in [zone]
    }

    if not zones_to_check:
        return

    async with CloudflareProvider(
        api_token=api_token,
        api_key=api_key,
        api_email=api_email,
    ) as provider:
        waf_statuses = await provider.get_waf_status_batch(list(zones_to_check.items()))

    # Update results with WAF status
    for result in results:
        if zone := hostname_to_zone.get(result.hostname):
            zone_id, _ = zone
            result.waf_status = waf_statuses.get(zone_id)


app = typer.Typer(
    name="react2scan",
    help="🔍 Scan your infrastructure for React2Shell vulnerabilities",
    no_args_is_help=False,  # We handle this ourselves
    rich_markup_mode="rich",
    pretty_exceptions_enable=True,
)


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console = Console()
        console.print_banner()
        typer.echo(f"v{__version__}")
        raise typer.Exit()


def help_callback(ctx: typer.Context, value: bool) -> None:
    """Print banner and help."""
    if value:
        _print_banner_and_help(ctx)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-V",
            help="Show version and exit.",
            callback=version_callback,
            is_eager=True,
        ),
    ] = None,
    help_: Annotated[
        bool | None,
        typer.Option(
            "--help",
            "-h",
            help="Show this message and exit.",
            is_eager=True,
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose/debug logging"),
    ] = False,
    log_file: Annotated[
        Path | None,
        typer.Option("--log-file", help="Save logs to file"),
    ] = None,
) -> None:
    """
    🔍 [bold cyan]react2scan[/] - Infrastructure vulnerability scanner

    Scan your Cloudflare infrastructure for Next.js React2Shell vulnerabilities
    (CVE-2025-55182).

    [bold]Quick Start:[/]

      [green]1.[/] Set your API token:
         [dim]export CLOUDFLARE_API_TOKEN="your-token"[/]

      [green]2.[/] Run a scan:
         [dim]react2scan scan cloudflare[/]

    [bold]Or try the guided setup:[/]
         [dim]react2scan quickstart[/]
    """
    # Configure logging based on verbosity
    log_level = logging.DEBUG if verbose else logging.INFO
    configure_logging(level=log_level, log_file=str(log_file) if log_file else None)

    if help_ or ctx.invoked_subcommand is None:
        # Show banner + help
        console = Console()
        console.print_banner()
        console.console.print(ctx.get_help())


@app.command()
def quickstart() -> None:
    """
    🚀 Interactive guided setup - the easiest way to get started!

    Walks you through setting up your first scan step by step.
    """
    console = Console()
    console.print_banner()

    console.console.print(
        Panel(
            "[bold]Welcome to react2scan![/]\n\n"
            "This wizard will help you scan your infrastructure for\n"
            "React2Shell vulnerabilities.\n\n"
            "[dim]Press Ctrl+C at any time to exit.[/]",
            border_style="cyan",
        )
    )
    console.console.print()

    # Check for existing token
    token = os.environ.get("CLOUDFLARE_API_TOKEN")

    if token:
        console.print_success("Found CLOUDFLARE_API_TOKEN in environment")
        use_existing = typer.confirm("Use this token?", default=True)
        if not use_existing:
            token = None

    if not token:
        console.console.print()
        console.console.print("[bold]Step 1:[/] Cloudflare API Token")
        console.console.print()
        console.console.print("  You need a Cloudflare API token with these permissions:")
        console.console.print("    • [cyan]Zone:Read[/] - to list your domains")
        console.console.print("    • [cyan]DNS:Read[/] - to read DNS records")
        console.console.print()
        console.console.print(
            "  [dim]Create one at: https://dash.cloudflare.com/profile/api-tokens[/]"
        )
        console.console.print()

        token = typer.prompt("Enter your Cloudflare API token", hide_input=True)

    # Ask about output
    console.console.print()
    console.console.print("[bold]Step 2:[/] Output Options")
    console.console.print()
    save_results = typer.confirm("Save results to a JSON file?", default=False)
    output_file = None
    if save_results:
        output_file = typer.prompt("Output filename", default="scan-results.json")

    # Confirm and run
    console.console.print()
    console.console.print("[bold]Step 3:[/] Ready to scan!")
    console.console.print()
    console.console.print("  [dim]This will:[/]")
    console.console.print("    1. Connect to Cloudflare and discover your domains")
    console.console.print("    2. Find all DNS records (A, AAAA, CNAME)")
    console.console.print("    3. Scan each hostname for vulnerabilities")
    console.console.print("    4. Use [green]safe detection[/] (no code execution)")
    console.console.print()

    if not typer.confirm("Start the scan?", default=True):
        console.print_info("Scan cancelled")
        raise typer.Exit(0)

    console.console.print()

    # Run the scan
    _run_scan_flow(
        console=console,
        provider="cloudflare",
        api_token=token,
        api_key=None,
        api_email=None,
        output=Path(output_file) if output_file else None,
        threads=DEFAULT_THREADS,
        timeout=DEFAULT_TIMEOUT_SECONDS,
    )


@app.command()
def providers() -> None:
    """📦 List available infrastructure providers."""
    console = Console()
    console.print_banner()

    console.console.print("[bold]Available Providers:[/]\n")

    for name in list_providers():
        provider_cls = PROVIDERS[name]
        console.console.print(f"  [cyan]●[/] [bold]{name}[/] - {provider_cls.description}")

    console.console.print()
    console.console.print("[dim]Usage: react2scan scan <provider> --api-token <token>[/]")
    console.console.print()


@app.command(name="scanners")
def scanners_cmd() -> None:
    """🔬 List available vulnerability scanners."""
    console = Console()
    console.print_banner()

    console.console.print("[bold]Available Scanners:[/]\n")

    for name in list_scanners():
        scanner_cls = SCANNERS[name]
        cves = ", ".join(scanner_cls.cves) if scanner_cls.cves else "N/A"
        console.console.print(f"  [cyan]●[/] [bold]{name}[/]")
        console.console.print(f"      {scanner_cls.description}")
        console.console.print(f"      [dim]CVEs: {cves}[/]")

    console.console.print()


@app.command()
def discover(
    provider: Annotated[
        str | None,
        typer.Argument(help="Provider name (e.g., 'cloudflare')"),
    ] = None,
    api_token: Annotated[
        str | None,
        typer.Option(
            "--api-token",
            "-t",
            envvar="CLOUDFLARE_API_TOKEN",
            help="API token (or set CLOUDFLARE_API_TOKEN env var)",
        ),
    ] = None,
    api_key: Annotated[
        str | None,
        typer.Option("--api-key", envvar="CLOUDFLARE_API_KEY", hidden=True),
    ] = None,
    api_email: Annotated[
        str | None,
        typer.Option("--api-email", envvar="CLOUDFLARE_EMAIL", hidden=True),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Save to JSON file (recommended)"),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Minimal output"),
    ] = False,
) -> None:
    """
    🔎 Discover domains & DNS records from your infrastructure.

    [bold]Examples:[/]

      [dim]# Discover and save to file[/]
      react2scan discover cloudflare -o infra.json

      [dim]# Using environment variable[/]
      export CLOUDFLARE_API_TOKEN="your-token"
      react2scan discover cloudflare -o infra.json

      [dim]# Passing token directly[/]
      react2scan discover cloudflare -t "your-token"

    """
    console = Console(quiet=quiet)

    if not quiet:
        console.print_banner()

    # Handle missing provider
    if not provider:
        console.console.print("[bold]Usage:[/] react2scan discover <provider> [OPTIONS]")
        console.console.print()
        console.console.print("[bold]Available providers:[/]")
        for name in list_providers():
            provider_cls = PROVIDERS[name]
            console.console.print(f"  [cyan]●[/] [bold]{name}[/] - {provider_cls.description}")
        console.console.print()
        console.console.print("[bold]Examples:[/]")
        console.console.print("  [dim]react2scan discover cloudflare -o infra.json[/]")
        console.console.print("  [dim]react2scan discover cloudflare -t 'token' -o infra.json[/]")
        console.console.print()
        console.console.print("[dim]Tip: Always use -o to save the infrastructure map[/]")
        raise typer.Exit(0)

    # Validate provider
    provider_cls = get_provider(provider)
    if provider_cls is None:
        console.print_error(f"Unknown provider: [bold]{provider}[/]")
        console.console.print()
        console.console.print("Available providers:")
        for name in list_providers():
            console.console.print(f"  • {name}")
        console.console.print()
        console.console.print("[dim]Try: react2scan providers[/]")
        raise typer.Exit(1)

    # Warn if no output file specified
    if not output and not quiet:
        console.print_warning("No output file specified. Results won't be saved.")
        console.console.print("[dim]  Use -o infra.json to save for later scanning[/]")
        console.console.print()

    # Validate credentials with helpful message
    if provider == "cloudflare":
        _validate_cloudflare_credentials(console, api_token, api_key, api_email)

    logger.debug(f"Starting discovery for provider: {provider}")

    async def run_discovery() -> InfrastructureMap:
        if provider == "cloudflare":
            from react2scan.providers.cloudflare import CloudflareProvider

            async with CloudflareProvider(
                api_token=api_token,
                api_key=api_key,
                api_email=api_email,
            ) as prov:
                console.print_info("Validating credentials...")
                await prov.validate_credentials()
                console.print_success("Credentials valid")

                console.print_info("Discovering infrastructure...")
                return await prov.discover()
        else:
            raise ValueError(f"Provider {provider} not implemented")

    try:
        infra = asyncio.run(run_discovery())
    except Exception as e:
        console.print_error(f"Discovery failed: {e}")
        raise typer.Exit(1) from e

    # Display results
    console.print_success(
        f"Found [bold]{len(infra.domains)}[/] domains with [bold]{infra.total_records}[/] records"
    )
    console.console.print()
    console.print_infrastructure_map(infra)

    # Save to file if requested
    if output:
        output.write_text(infra.model_dump_json(indent=2))
        console.print_success(f"Saved to [bold]{output}[/]")
        console.console.print()
        console.console.print("[dim]Next step: react2scan scan --from-file " + str(output) + "[/]")


@app.command()
def scan(
    provider: Annotated[
        str | None,
        typer.Argument(help="Provider name (e.g., 'cloudflare')"),
    ] = None,
    from_file: Annotated[
        Path | None,
        typer.Option("--from-file", "-f", help="Load from JSON file instead of discovering"),
    ] = None,
    api_token: Annotated[
        str | None,
        typer.Option(
            "--api-token",
            "-t",
            envvar="CLOUDFLARE_API_TOKEN",
            help="API token (or set CLOUDFLARE_API_TOKEN env var)",
        ),
    ] = None,
    api_key: Annotated[
        str | None,
        typer.Option("--api-key", envvar="CLOUDFLARE_API_KEY", hidden=True),
    ] = None,
    api_email: Annotated[
        str | None,
        typer.Option("--api-email", envvar="CLOUDFLARE_EMAIL", hidden=True),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Save results to JSON file"),
    ] = None,
    paths: Annotated[
        str | None,
        typer.Option(
            "--paths",
            "-p",
            help="Comma-separated paths to scan (default: /, /_next)",
        ),
    ] = None,
    threads: Annotated[
        int,
        typer.Option("--threads", "-c", help="Concurrent connections"),
    ] = DEFAULT_THREADS,
    timeout: Annotated[
        int,
        typer.Option("--timeout", help="Request timeout in seconds"),
    ] = DEFAULT_TIMEOUT_SECONDS,
    verify_ssl: Annotated[
        bool,
        typer.Option(
            "--verify-ssl/--no-verify-ssl",
            help="Verify SSL certificates (default: disabled for internal scanning)",
        ),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="Show what would be scanned without scanning"),
    ] = False,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Only show vulnerabilities"),
    ] = False,
) -> None:
    """
    🎯 Scan for React2Shell vulnerabilities.

    Uses safe detection mode - no code is executed on targets.

    [bold]Quick Start:[/]

      [dim]# Set your token and scan[/]
      export CLOUDFLARE_API_TOKEN="your-token"
      react2scan scan cloudflare

    [bold]Examples:[/]

      [dim]# Scan with token[/]
      react2scan scan cloudflare -t "your-token"

      [dim]# Scan from saved infrastructure file[/]
      react2scan scan -f infra.json

      [dim]# Fast scan with more threads[/]
      react2scan scan cloudflare --threads 50

      [dim]# Scan custom paths[/]
      react2scan scan cloudflare -p "/,/api,/admin"

      [dim]# Preview targets without scanning[/]
      react2scan scan cloudflare --dry-run
    """
    console = Console(quiet=quiet)

    if not quiet:
        console.print_banner()

    # Validate input with helpful message
    if not provider and not from_file:
        console.console.print("[bold]Usage:[/] react2scan scan <provider> [OPTIONS]")
        console.console.print("       react2scan scan -f <file.json> [OPTIONS]")
        console.console.print()
        console.console.print("[bold]Available providers:[/]")
        for name in list_providers():
            prov_cls = PROVIDERS[name]
            console.console.print(f"  [cyan]●[/] [bold]{name}[/] - {prov_cls.description}")
        console.console.print()
        console.console.print("[bold]Examples:[/]")
        console.console.print("  [dim]react2scan scan cloudflare -t 'your-token'[/]")
        console.console.print("  [dim]react2scan scan -f infra.json[/]")
        console.console.print()
        console.console.print("[dim]Tip: Run 'react2scan quickstart' for guided setup[/]")
        raise typer.Exit(0)

    # Parse and validate custom paths if provided
    scan_paths: list[str] | None = None
    if paths:
        try:
            scan_paths = _validate_paths(paths)
        except typer.BadParameter as e:
            console.print_error(f"Invalid path: {e}")
            raise typer.Exit(1) from e

    _run_scan_flow(
        console=console,
        provider=provider,
        api_token=api_token,
        api_key=api_key,
        api_email=api_email,
        from_file=from_file,
        output=output,
        threads=threads,
        timeout=timeout,
        paths=scan_paths,
        verify_ssl=verify_ssl,
        dry_run=dry_run,
    )


def _run_scan_flow(
    console: Console,
    provider: str | None,
    api_token: str | None,
    api_key: str | None,
    api_email: str | None,
    output: Path | None,
    threads: int,
    timeout: int,
    from_file: Path | None = None,
    paths: list[str] | None = None,
    verify_ssl: bool = False,
    dry_run: bool = False,
) -> None:
    """Internal function to run the scan flow."""
    # Load or discover infrastructure
    infra: InfrastructureMap

    if from_file:
        if not from_file.exists():
            console.print_error(f"File not found: [bold]{from_file}[/]")
            raise typer.Exit(1)

        console.print_info(f"Loading from {from_file}...")

        # Read file content
        try:
            file_content = from_file.read_text()
        except OSError as e:
            console.print_error(f"Failed to read file: {e}")
            raise typer.Exit(1) from e

        # Parse JSON
        try:
            data = json.loads(file_content)
        except json.JSONDecodeError as e:
            console.print_error(f"Invalid JSON in file: {e.msg} (line {e.lineno}, col {e.colno})")
            raise typer.Exit(1) from e

        # Validate schema
        try:
            infra = InfrastructureMap.model_validate(data)
        except ValidationError as e:
            console.print_error("Invalid infrastructure map format:")
            for error in e.errors():
                loc = ".".join(str(x) for x in error["loc"])
                console.console.print(f"  [dim]{loc}:[/dim] {error['msg']}")
            raise typer.Exit(1) from e

        console.print_success(
            f"Loaded [bold]{len(infra.domains)}[/] domains, "
            f"[bold]{infra.total_scannable}[/] targets"
        )
        logger.debug(f"Loaded infrastructure from {from_file}: {len(infra.domains)} domains")
    else:
        # Validate provider credentials
        if provider == "cloudflare":
            _validate_cloudflare_credentials(console, api_token, api_key, api_email)

        logger.debug(f"Starting discovery for provider: {provider}")

        async def run_discovery() -> InfrastructureMap:
            if provider == "cloudflare":
                from react2scan.providers.cloudflare import CloudflareProvider

                async with CloudflareProvider(
                    api_token=api_token,
                    api_key=api_key,
                    api_email=api_email,
                ) as prov:
                    console.print_info("Validating credentials...")
                    await prov.validate_credentials()
                    console.print_info("Discovering your infrastructure...")
                    return await prov.discover()
            else:
                raise ValueError(f"Provider {provider} not implemented")

        try:
            infra = asyncio.run(run_discovery())
        except Exception as e:
            console.print_error(f"Discovery failed: {e}")
            raise typer.Exit(1) from e

        console.print_success(
            f"Found [bold]{len(infra.domains)}[/] domains, [bold]{infra.total_scannable}[/] targets"
        )

    console.print_infrastructure_map(infra)

    # Build hostname -> zone mapping for WAF lookups
    hostname_to_zone: dict[str, tuple[str, str]] = {}
    for domain in infra.domains:
        for record in domain.records:
            hostname_to_zone[record.name] = (domain.zone_id, domain.name)

    # Check if there are targets to scan
    if infra.total_scannable == 0:
        console.print_warning("No scannable targets found")
        console.console.print("[dim]Need A or AAAA records to scan[/]")
        raise typer.Exit(0)

    # Handle dry-run mode
    if dry_run:
        console.print_info("[bold]Dry run mode[/bold] - showing targets without scanning")
        console.console.print()
        targets = infra.get_all_targets()
        for _domain, record in targets:
            console.console.print(f"  [cyan]●[/] {record.name}")
        console.console.print()
        console.print_info(f"Would scan {len(targets)} targets")
        raise typer.Exit(0)

    # Show scan info
    console.print_info(f"Scanning {infra.total_scannable} targets...")
    console.console.print()

    async def run_scan() -> ScanReport:
        async with React2ShellScanner(
            timeout=timeout,
            threads=threads,
            paths=paths,
            verify_ssl=verify_ssl,
        ) as scanner:
            report = ScanReport(
                infrastructure=infra,
                scanner=scanner.name,
                started_at=datetime.now(timezone.utc),
                options={
                    "threads": threads,
                    "timeout": timeout,
                },
            )

            # Track vulnerable results for WAF check
            vulnerable_results: list[ScanResult] = []

            with console.create_scan_progress() as progress:
                task = progress.add_task("Scanning", total=infra.total_scannable)

                async for result in scanner.scan(infra):
                    report.results.append(result)
                    progress.advance(task)

                    if result.vulnerable:
                        vulnerable_results.append(result)
                        # Print initial finding (WAF status added later)
                        progress.console.print()
                        progress.console.print(
                            f"[bold red]🚨 VULNERABLE[/bold red] "
                            f"[white]{result.hostname}[/white]"
                        )

            report.completed_at = datetime.now(timezone.utc)

            # Enrich vulnerable results with WAF status (Cloudflare only)
            if vulnerable_results and infra.provider == "cloudflare":
                if api_token or api_key:
                    console.console.print()
                    console.print_info("Checking WAF status for vulnerable targets...")
                    await _enrich_with_waf_status(
                        vulnerable_results,
                        hostname_to_zone,
                        api_token,
                        api_key,
                        api_email,
                    )
                else:
                    console.console.print()
                    console.print_warning(
                        "Skipping WAF status check (no API credentials). "
                        "Set CLOUDFLARE_API_TOKEN to enable."
                    )

            return report

    try:
        report = asyncio.run(run_scan())
    except KeyboardInterrupt:
        console.print_warning("Scan interrupted")
        raise typer.Exit(130)
    except Exception as e:
        console.print_error(f"Scan failed: {e}")
        raise typer.Exit(1) from e

    # Print full vulnerable findings with WAF status
    if report.vulnerable_count > 0:
        console.console.print()
        console.console.rule("[bold red]Vulnerable Targets", style="red")
        console.console.print()
        for result in report.results:
            if result.vulnerable:
                console.print_vulnerable(result)
                console.console.print()

    # Print summary
    console.print_scan_summary(report)

    # Save results if requested
    if output:
        output.write_text(report.model_dump_json(indent=2))
        console.print_success(f"Results saved to [bold]{output}[/]")

    # Exit with error code if vulnerabilities found
    if report.vulnerable_count > 0:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
