import hashlib

from rich.console import Console
from rich.panel import Panel

console = Console()


def run_hash(text: str, algo: str) -> None:
    algorithm = algo.lower()
    if algorithm not in ("sha256", "sha512", "md5"):
        algorithm = "sha256"

    if algorithm == "sha256":
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    elif algorithm == "sha512":
        digest = hashlib.sha512(text.encode("utf-8")).hexdigest()
    else:
        digest = hashlib.md5(text.encode("utf-8")).hexdigest()

    content = (
        f"[bold]Algorithm:[/] {algorithm}\n"
        f"[bold]Input:[/] {text}\n"
        f"[bold]Digest:[/] {digest}"
    )
    console.print(Panel(content, title=f"[bold cyan]Hash Output[/]", border_style="cyan"))
    if algorithm == "md5":
        console.print(Panel(
            "[bold yellow]Warning: MD5 is not recommended for passwords or security-critical use.[/]",
            border_style="yellow",
            title="Warning"
        ))
