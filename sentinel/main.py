import sys
import typer
from rich.console import Console
from rich.panel import Panel

from sentinel import __version__
from sentinel.config import ETHICAL_MESSAGE, APP_NAME
from sentinel.dns_lookup import run_dns
from sentinel.hashing import run_hash
from sentinel.headers import run_headers
from sentinel.ip import run_ip
from sentinel.password import run_password
from sentinel.ports import run_ports
from sentinel.reports import run_report
from sentinel.scanner import run_scan
from sentinel.ssl_checker import run_ssl
from sentinel.whois_lookup import run_whois
from sentinel.utils import is_valid_domain, normalize_domain, print_error

console = Console(
    file=sys.stdout,
    force_terminal=sys.stdout.isatty(),
    no_color=not sys.stdout.isatty(),
    color_system=None,
    legacy_windows=False,
)
app = typer.Typer(
    name="sentinel",
    help="SENTINEL - Cybersecurity Intelligence CLI. Analyze. Detect. Secure.",
    add_completion=False,
)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    panel_text = (
        f"[bold cyan]{APP_NAME}[/bold cyan] - Analyze. Detect. Secure.\n"
        f"Version: [green]{__version__}[/green]\n\n"
        "1. scan <domain>\n"
        "2. ssl <domain>\n"
        "3. dns <domain>\n"
        "4. whois <domain>\n"
        "5. headers <domain>\n"
        "6. ports <domain>\n"
        "7. ip [ip-address]\n"
        "8. password [--length INT] [--no-symbols]\n"
        "9. hash [--algo sha256|sha512|md5] <text>\n"
        "10. report <domain>"
    )

    console.print(Panel(ETHICAL_MESSAGE, title="[bold yellow]Disclaimer[/]", border_style="yellow"))
    console.print(Panel(panel_text, title=f"[bold cyan]{APP_NAME}[/]", border_style="bold cyan"))
    if ctx.invoked_subcommand is None:
        return


@app.command()
def scan(domain: str) -> None:
    normalized = normalize_domain(domain)
    if not is_valid_domain(normalized):
        print_error("Invalid domain format.")
        raise typer.Exit(code=1)
    run_scan(normalized)


@app.command()
def ssl(domain: str) -> None:
    normalized = normalize_domain(domain)
    if not is_valid_domain(normalized):
        print_error("Invalid domain format.")
        raise typer.Exit(code=1)
    run_ssl(normalized)


@app.command()
def dns(domain: str) -> None:
    normalized = normalize_domain(domain)
    if not is_valid_domain(normalized):
        print_error("Invalid domain format.")
        raise typer.Exit(code=1)
    run_dns(normalized)


@app.command()
def whois(domain: str) -> None:
    normalized = normalize_domain(domain)
    if not is_valid_domain(normalized):
        print_error("Invalid domain format.")
        raise typer.Exit(code=1)
    run_whois(normalized)


@app.command()
def headers(domain: str) -> None:
    normalized = normalize_domain(domain)
    if not is_valid_domain(normalized):
        print_error("Invalid domain format.")
        raise typer.Exit(code=1)
    run_headers(normalized)


@app.command()
def ports(domain: str) -> None:
    normalized = normalize_domain(domain)
    if not is_valid_domain(normalized):
        print_error("Invalid domain format.")
        raise typer.Exit(code=1)
    run_ports(normalized)


@app.command()
def ip(target: str | None = typer.Argument(None, help="IP address to look up.")) -> None:
    run_ip(target)


@app.command()
def password(length: int = typer.Option(16, help="Password length."), no_symbols: bool = typer.Option(False, help="Exclude symbols.")) -> None:
    run_password(length, no_symbols)


@app.command(name="hash")
def hash_command(text: str, algo: str = typer.Option("sha256", help="Hash algorithm.")) -> None:
    run_hash(text, algo)


@app.command()
def report(domain: str) -> None:
    normalized = normalize_domain(domain)
    if not is_valid_domain(normalized):
        print_error("Invalid domain format.")
        raise typer.Exit(code=1)
    run_report(normalized)


def cli():
    app()


if __name__ == "__main__":
    cli()
