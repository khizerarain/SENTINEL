from datetime import datetime

import whois
from rich.console import Console
from rich.panel import Panel

console = Console()


def _format_value(value):
    if value is None:
        return "N/A"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    return str(value)


def run_whois(domain: str) -> None:
    try:
        record = whois.whois(domain)
    except Exception as exc:
        console.print(Panel(f"[bold red]WHOIS lookup failed: {exc}[/]", border_style="red", title="Error"))
        return

    registrar = _format_value(record.registrar)
    creation = _format_value(record.creation_date)
    expiration = _format_value(record.expiration_date)
    updated = _format_value(record.updated_date)
    nameservers = _format_value(record.name_servers)
    status = _format_value(record.status)

    content = (
        f"[bold]Registrar:[/] {registrar}\n"
        f"[bold]Created:[/] {creation}\n"
        f"[bold]Expires:[/] {expiration}\n"
        f"[bold]Updated:[/] {updated}\n"
        f"[bold]Name Servers:[/] {nameservers}\n"
        f"[bold]Status:[/] {status}"
    )

    console.print(Panel(content, title=f"[bold cyan]WHOIS Data for {domain}[/]", border_style="cyan"))
