import re
import sys
import time
from typing import Any

import requests
from rich.console import Console
from rich.panel import Panel

from config import ETHICAL_MESSAGE

console = Console(
    file=sys.stdout,
    force_terminal=sys.stdout.isatty(),
    no_color=not sys.stdout.isatty(),
    color_system=None,
    legacy_windows=False,
)

DOMAIN_REGEX = re.compile(r"^(?:https?://)?(?:[\w-]+\.)+[\w-]{2,63}(?:/.*)?$")


def normalize_domain(domain: str) -> str:
    domain = domain.strip()
    domain = re.sub(r"^https?://", "", domain, flags=re.I)
    domain = domain.rstrip("/")
    return domain


def is_valid_domain(domain: str) -> bool:
    domain = normalize_domain(domain)
    return bool(DOMAIN_REGEX.match(domain))


def make_request(url: str) -> requests.Response | None:
    try:
        with console.status("[bold cyan]Connecting...[/]", spinner="dots"):
            response = requests.get(url, timeout=10, headers={"User-Agent": "SENTINEL/1.0"})
        return response
    except requests.RequestException as exc:
        print_error(f"Request failed: {exc}")
        return None


def print_error(msg: str) -> None:
    console.print(Panel(f"[bold red]{msg}[/]", border_style="red", title="Error"))


def print_success(msg: str) -> None:
    console.print(Panel(f"[bold green]{msg}[/]", border_style="green", title="Success"))


def compute_security_score(results: dict[str, Any]) -> int:
    score = 0
    if results.get("https_enabled"):
        score += 20
    if results.get("valid_ssl"):
        score += 20
    headers_present = results.get("headers_present")
    if isinstance(headers_present, list):
        score += min(60, len(headers_present) * 10)
    return min(100, score)
