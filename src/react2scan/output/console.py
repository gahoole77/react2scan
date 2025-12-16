"""Rich console output for react2scan."""

from rich.console import Console as RichConsole
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from react2scan.models import (
    InfrastructureMap,
    ScanReport,
    ScanResult,
    VulnerabilityStatus,
)

# ASCII art banner
BANNER = """\
[bold cyan]
                        _   ___
                       | | |__ \\
   _ __ ___  __ _  ___| |_   ) |___  ___ __ _ _ __
  | '__/ _ \\/ _` |/ __| __| / // __|/ __/ _` | '_ \\
  | | |  __/ (_| | (__| |_ / /_\\__ \\ (_| (_| | | | |
  |_|  \\___|\\__,_|\\___|\\__|____|___/\\___\\__,_|_| |_|
[/bold cyan]\
                      [dim]by[/dim] [bold white]Miggo Security[/bold white]

[dim]────────────────────────────────────────────────────────[/dim]
[yellow] Next.js / RSC Infrastructure Scanner for CVE-2025-55182[/yellow]
[dim]────────────────────────────────────────────────────────[/dim]"""


class Console:
    """Rich console output handler for react2scan."""

    def __init__(self, quiet: bool = False, no_color: bool = False) -> None:
        """
        Initialize the console.

        Args:
            quiet: Suppress non-essential output.
            no_color: Disable colored output.
        """
        self.quiet = quiet
        self.console = RichConsole(
            force_terminal=not no_color,
            no_color=no_color,
        )

    def print_banner(self) -> None:
        """Print the application banner with ASCII art."""
        if self.quiet:
            return

        self.console.print(BANNER)
        self.console.print()

    def print_info(self, message: str) -> None:
        """Print an info message."""
        if self.quiet:
            return
        self.console.print(f"[cyan]ℹ[/cyan] {message}")

    def print_success(self, message: str) -> None:
        """Print a success message."""
        self.console.print(f"[green]✓[/green] {message}")

    def print_warning(self, message: str) -> None:
        """Print a warning message."""
        self.console.print(f"[yellow]⚠[/yellow] {message}")

    def print_error(self, message: str) -> None:
        """Print an error message."""
        self.console.print(f"[red]✗[/red] {message}")

    def print_vulnerable(self, result: ScanResult) -> None:
        """Print a vulnerability finding."""
        target_info = f" [dim]({result.target_ip})[/dim]" if result.target_ip else ""
        self.console.print(
            f"[bold red]🚨 VULNERABLE[/bold red] "
            f"[white]{result.hostname}[/white]{target_info}"
        )
        if result.details:
            self.console.print(f"   [dim]{result.details}[/dim]")
        if result.tested_path:
            self.console.print(f"   [dim]Path: {result.tested_path}[/dim]")

        # Display WAF status if available
        if result.waf_status:
            waf = result.waf_status
            if waf.error:
                self.console.print(f"   [yellow]WAF: Unable to check ({waf.error})[/yellow]")
            elif waf.managed_ruleset_enabled:
                self.console.print(
                    "   [yellow]WAF: Enabled[/yellow] "
                    "[dim](may slow attackers, but patch ASAP)[/dim]"
                )
            else:
                self.console.print(
                    "   [bold red]WAF: Not enabled[/bold red] "
                    "[dim](immediately exploitable - patch now!)[/dim]"
                )

    def print_infrastructure_map(self, infra: InfrastructureMap) -> None:
        """Print a summary of discovered infrastructure."""
        if self.quiet:
            return

        table = Table(
            title="Discovered Infrastructure",
            title_style="bold cyan",
            border_style="dim",
        )
        table.add_column("Domain", style="white")
        table.add_column("Records", justify="right", style="cyan")
        table.add_column("Scannable", justify="right", style="green")
        table.add_column("Proxied", justify="right", style="yellow")

        for domain in infra.domains:
            scannable = len(domain.scannable_records)
            proxied = sum(1 for r in domain.records if r.proxied)
            table.add_row(
                domain.name,
                str(domain.record_count),
                str(scannable),
                str(proxied) if proxied else "-",
            )

        self.console.print(table)
        self.console.print()

        # Summary
        self.console.print(
            f"[cyan]Provider:[/cyan] {infra.provider}  "
            f"[cyan]Domains:[/cyan] {len(infra.domains)}  "
            f"[cyan]Total Records:[/cyan] {infra.total_records}  "
            f"[cyan]Scannable:[/cyan] {infra.total_scannable}"
        )
        self.console.print()

    def print_scan_summary(self, report: ScanReport) -> None:
        """Print scan summary."""
        self.console.print()
        self.console.rule("[bold]Scan Summary", style="cyan")
        self.console.print()

        # Stats
        total = len(report.results)
        vulnerable = report.vulnerable_count
        errors = report.error_count
        clean = total - vulnerable - errors

        stats = Table.grid(padding=(0, 4))
        stats.add_column(justify="right")
        stats.add_column()

        stats.add_row("[dim]Total scanned:[/dim]", str(total))

        if vulnerable > 0:
            stats.add_row(
                "[bold red]Vulnerable:[/bold red]",
                f"[bold red]{vulnerable}[/bold red]",
            )
        else:
            stats.add_row("[dim]Vulnerable:[/dim]", "0")

        stats.add_row("[dim]Clean:[/dim]", str(clean))

        if errors > 0:
            stats.add_row("[yellow]Errors:[/yellow]", str(errors))

        self.console.print(stats)

        # WAF status breakdown for vulnerable targets
        if vulnerable > 0:
            vuln_results = [r for r in report.results if r.vulnerable]
            waf_protected = sum(
                1 for r in vuln_results
                if r.waf_status and r.waf_status.managed_ruleset_enabled
            )
            waf_unprotected = sum(
                1 for r in vuln_results
                if r.waf_status and not r.waf_status.managed_ruleset_enabled
            )
            waf_unknown = vulnerable - waf_protected - waf_unprotected

            self.console.print()
            self.console.print(
                "[bold]WAF Status:[/bold] [dim](patch all - WAF can be bypassed)[/dim]"
            )
            waf_stats = Table.grid(padding=(0, 4))
            waf_stats.add_column(justify="right")
            waf_stats.add_column()

            if waf_unprotected > 0:
                waf_stats.add_row(
                    "[bold red]No WAF:[/bold red]",
                    f"[bold red]{waf_unprotected}[/bold red] [dim](critical - patch now)[/dim]",
                )
            if waf_protected > 0:
                waf_stats.add_row(
                    "[yellow]WAF enabled:[/yellow]",
                    f"[yellow]{waf_protected}[/yellow] [dim](still vulnerable - patch soon)[/dim]",
                )
            if waf_unknown > 0:
                waf_stats.add_row(
                    "[dim]Unknown:[/dim]",
                    f"{waf_unknown} [dim](could not check)[/dim]",
                )

            self.console.print(waf_stats)

        # Duration
        if report.completed_at and report.started_at:
            duration = report.completed_at - report.started_at
            self.console.print(f"\n[dim]Duration: {duration.total_seconds():.1f}s[/dim]")

    def create_discovery_progress(self) -> Progress:
        """Create a progress bar for discovery."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}[/cyan]"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
            disable=self.quiet,
        )

    def create_scan_progress(self) -> Progress:
        """Create a progress bar for scanning."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Scanning[/cyan]"),
            BarColumn(),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
            disable=self.quiet,
        )

    def print_result_inline(self, result: ScanResult) -> None:
        """Print a single scan result inline (for streaming output)."""
        if result.status == VulnerabilityStatus.VULNERABLE:
            self.print_vulnerable(result)
        elif result.status == VulnerabilityStatus.ERROR and not self.quiet:
            self.console.print(
                f"[yellow]![/yellow] {result.hostname} [dim]- {result.details}[/dim]"
            )
