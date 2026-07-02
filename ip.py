import ipaddress
import requests

from rich.console import Console
from rich.panel import Panel

console = Console()


def run_ip(target: str | None = None) -> None:
    if not target:
        response = requests.get("http://ip-api.com/json/", timeout=10)
        data = response.json()
    else:
        try:
            ip = ipaddress.ip_address(target)
            if ip.is_private:
                console.print(Panel(
                    "[bold yellow]Private/Local IP — no geolocation available.[/]",
                    border_style="yellow",
                    title="IP Lookup"
                ))
                return
        except ValueError:
            console.print(Panel(
                "[bold red]Invalid IP address provided.[/]",
                border_style="red",
                title="IP Lookup"
            ))
            return
        response = requests.get(f"http://ip-api.com/json/{target}", timeout=10)
        data = response.json()

    if data.get("status") != "success":
        console.print(Panel(
            "[bold red]IP lookup failed.[/]",
            border_style="red",
            title="IP Lookup"
        ))
        return

    content = (
        f"[bold]IP:[/] {data.get('query', 'N/A')}\n"
        f"[bold]Country:[/] {data.get('country', 'N/A')}\n"
        f"[bold]Region:[/] {data.get('regionName', 'N/A')}\n"
        f"[bold]City:[/] {data.get('city', 'N/A')}\n"
        f"[bold]ISP:[/] {data.get('isp', 'N/A')}\n"
        f"[bold]Org:[/] {data.get('org', 'N/A')}\n"
        f"[bold]Timezone:[/] {data.get('timezone', 'N/A')}\n"
        f"[bold]Latitude/Longitude:[/] {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}"
    )
    console.print(Panel(content, title="IP Geolocation", border_style="cyan"))
