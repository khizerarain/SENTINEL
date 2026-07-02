import dns.resolver

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def _fetch_records(domain: str, record_type: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=10)
        return [str(rdata).strip() for rdata in answers]
    except Exception:
        return []


def run_dns(domain: str) -> None:
    record_types = ["A", "AAAA", "MX", "TXT", "NS"]
    table = Table(title=f"DNS Records for {domain}", border_style="cyan")
    table.add_column("Record Type", style="bold")
    table.add_column("Value")

    for record_type in record_types:
        values = _fetch_records(domain, record_type)
        if not values:
            table.add_row(record_type, "N/A")
        else:
            for index, value in enumerate(values):
                table.add_row(record_type if index == 0 else "", value)

    console.print(Panel(table, border_style="bold cyan"))
