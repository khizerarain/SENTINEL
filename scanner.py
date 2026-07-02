import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import config
from config import SECURITY_HEADERS
from headers import get_security_header_results
from ports import scan_ports
from ssl_checker import get_ssl_details
from utils import compute_security_score, make_request

console = Console()


def run_scan(domain: str) -> None:
    url = f"https://{domain}"
    offline = False
    server_header = "N/A"
    response_time_ms = None
    https_enabled = False

    with console.status("[bold cyan]Scanning target...[/]", spinner="dots"):
        response = make_request(url)
    if response is None:
        offline = True
    else:
        https_enabled = response.url.startswith("https://")
        server_header = response.headers.get("Server", "N/A")
        response_time_ms = int(response.elapsed.total_seconds() * 1000)

    ssl_data = get_ssl_details(domain, silent=True)
    header_data = get_security_header_results(domain)
    port_data = scan_ports(domain, silent=True)

    results = {
        "https_enabled": https_enabled,
        "valid_ssl": ssl_data.get("valid_ssl", False),
        "headers_present": header_data.get("present_headers", []),
    }
    score = compute_security_score(results)
    score_color = "green" if score >= 80 else "yellow" if score >= 50 else "red"

    panel = Panel(
        "",
        title=f"[bold cyan]SENTINEL Scan Results for {domain}[/]",
        border_style="bold cyan",
    )

    table = Table(show_header=False, box=None)
    table.add_row("Status:", "[green]Online[/green]" if not offline else "[red]Offline or unreachable[/red]")
    table.add_row("HTTPS Enabled:", f"[green]{https_enabled}[/green]" if https_enabled else "[red]{https_enabled}[/red]")
    table.add_row("Server Header:", server_header)
    table.add_row("Response Time:", f"{response_time_ms} ms" if response_time_ms is not None else "N/A")
    table.add_row("SSL Valid:", "[green]Yes[/green]" if ssl_data.get("valid_ssl") else "[red]No[/red]")
    table.add_row("SSL Issuer:", ssl_data.get("issuer", "N/A"))
    table.add_row("Days until expiry:", str(ssl_data.get("days_remaining", "N/A")))
    table.add_row("Security Score:", f"[{score_color}]{score}/100[/{score_color}]")
    table.add_row("Security Headers Present:", ", ".join(header_data.get("present_headers", [])) or "None")
    table.add_row("Open Ports:", ", ".join([str(port) for port in port_data.get("open_ports", [])]) or "None")

    console.print(Panel(table, title=f"[bold cyan]SENTINEL Scan Summary[/]", border_style="cyan"))

    recommendations = []
    missing_headers = header_data.get("missing_headers", [])
    if missing_headers:
        recommendations.append(f"Add missing security headers: {', '.join(missing_headers)}")
    if not https_enabled:
        recommendations.append("Enable HTTPS with a valid certificate.")
    if ssl_data.get("valid_ssl") is False:
        recommendations.append("Renew or fix the SSL/TLS certificate.")
    if ssl_data.get("days_remaining") is not None and ssl_data["days_remaining"] < 30:
        recommendations.append("Renew SSL certificate before expiration.")
    if port_data.get("open_ports"):
        recommendations.append(f"Review exposed open ports: {', '.join(str(port) for port in port_data['open_ports'])}")

    if recommendations:
        recommendation_panel = Panel(
            "\n".join(f"- {item}" for item in recommendations),
            title="Recommendations",
            border_style="yellow",
        )
        console.print(recommendation_panel)
    else:
        console.print(Panel("No immediate recommendations detected.", border_style="green", title="Recommendations"))
