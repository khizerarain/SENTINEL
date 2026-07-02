import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

import config
from utils import make_request

console = Console(
    file=sys.stdout,
    force_terminal=sys.stdout.isatty(),
    no_color=not sys.stdout.isatty(),
    color_system=None,
    legacy_windows=False,
)


def get_security_header_results(domain: str) -> dict:
    url = f"https://{domain}"
    response = make_request(url)
    present_headers = []
    missing_headers = []
    if response is None:
        return {"present_headers": [], "missing_headers": config.SECURITY_HEADERS}

    for header in config.SECURITY_HEADERS:
        if header in response.headers:
            present_headers.append(header)
        else:
            missing_headers.append(header)
    return {"present_headers": present_headers, "missing_headers": missing_headers}


def run_headers(domain: str) -> None:
    results = get_security_header_results(domain)
    table = Table(title=f"Security Headers for {domain}", border_style="cyan")
    table.add_column("Header Name", style="bold")
    table.add_column("Status")

    for header in config.SECURITY_HEADERS:
        status = "✅ Present" if header in results["present_headers"] else "❌ Missing"
        style = "green" if header in results["present_headers"] else "red"
        table.add_row(header, f"[{style}]{status}[/{style}]")

    console.print(Panel(table, border_style="bold cyan"))
    console.print(Panel(
        "Missing headers may expose your site to XSS, clickjacking, and other attacks.",
        border_style="yellow",
        title="Tip"
    ))
