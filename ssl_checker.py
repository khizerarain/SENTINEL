import socket
import ssl
from datetime import datetime

from rich.console import Console
from rich.panel import Panel

console = Console()


def _parse_name(name_tuple):
    parts = [item[0][1] for item in name_tuple if item]
    return ", ".join(parts) if parts else "N/A"


def get_ssl_details(domain: str, silent: bool = False) -> dict:
    context = ssl.create_default_context()
    details = {
        "valid_ssl": False,
        "issuer": "N/A",
        "subject": "N/A",
        "not_after": "N/A",
        "days_remaining": None,
        "algorithm": "Unknown",
    }
    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                details["valid_ssl"] = True
                issuer = cert.get("issuer")
                subject = cert.get("subject")
                details["issuer"] = _parse_name(issuer) if issuer else "N/A"
                details["subject"] = _parse_name(subject) if subject else "N/A"
                not_after = cert.get("notAfter")
                details["not_after"] = not_after or "N/A"
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    details["days_remaining"] = max(0, (expiry - datetime.utcnow()).days)
                cipher = ssock.cipher()
                if cipher and cipher[0]:
                    details["algorithm"] = cipher[0]
    except Exception as exc:
        details["valid_ssl"] = False
        if not silent:
            console.print(Panel(f"[bold red]SSL check failed: {exc}[/]", border_style="red", title="SSL Error"))
    return details


def run_ssl(domain: str) -> None:
    details = get_ssl_details(domain)
    rows = []
    rows.append(("Issuer:", details.get("issuer", "N/A")))
    rows.append(("Subject:", details.get("subject", "N/A")))
    rows.append(("Expires:", details.get("not_after", "N/A")))
    rows.append(("Days Remaining:", str(details.get("days_remaining", "N/A"))))
    rows.append(("Algorithm:", details.get("algorithm", "Unknown")))
    rows.append(("Valid SSL:", "Yes" if details.get("valid_ssl") else "No"))

    table_markup = "\n".join(f"[bold]{name}[/] {value}" for name, value in rows)
    console.print(Panel(table_markup, title=f"[bold cyan]SSL Certificate Details for {domain}[/]", border_style="cyan"))

    if details.get("days_remaining") is not None and details["days_remaining"] < 30:
        console.print(Panel("[bold yellow]Warning: Certificate expires in less than 30 days.[/]", border_style="yellow", title="Warning"))
