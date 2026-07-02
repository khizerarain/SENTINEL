import socket

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import config

console = Console()


def scan_ports(domain: str, silent: bool = False) -> dict:
    open_ports = []
    results = []
    for port, service in config.COMMON_PORTS.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((domain, port))
                status = "Open" if result == 0 else "Closed"
                results.append((port, service, status))
                if status == "Open":
                    open_ports.append(port)
        except Exception:
            results.append((port, service, "Closed"))
    return {"results": results, "open_ports": open_ports}


def run_ports(domain: str) -> None:
    data = scan_ports(domain)
    table = Table(title=f"Port Scan for {domain}", border_style="cyan")
    table.add_column("Port", style="bold")
    table.add_column("Service")
    table.add_column("Status")

    for port, service, status in data["results"]:
        color = "green" if status == "Open" else "red"
        table.add_row(str(port), service, f"[{color}]{status}[/{color}]")

    open_summary = ", ".join(str(port) for port in data["open_ports"]) or "None"
    console.print(Panel(table, border_style="bold cyan"))
    console.print(Panel(
        f"Open Ports: [bold]{open_summary}[/]\n\nOnly scan systems you own or have explicit permission to test.",
        border_style="yellow",
        title="Disclaimer"
    ))
