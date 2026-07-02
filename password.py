"""Generate cryptographically secure passwords using Python's secrets module."""

import sys
import secrets
import string

from rich.console import Console
from rich.panel import Panel

console = Console(
    file=sys.stdout,
    force_terminal=sys.stdout.isatty(),
    no_color=not sys.stdout.isatty(),
    color_system=None,
    legacy_windows=False,
)


def run_password(length: int, no_symbols: bool) -> None:
    if length < 4:
        length = 4

    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    symbols = string.punctuation if not no_symbols else ""

    alphabet = uppercase + lowercase + digits + symbols
    if not alphabet:
        alphabet = uppercase + lowercase + digits

    password_chars = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
    ]
    if symbols:
        password_chars.append(secrets.choice(symbols))

    while len(password_chars) < length:
        password_chars.append(secrets.choice(alphabet))

    secrets.SystemRandom().shuffle(password_chars)
    password = "".join(password_chars)

    strength_label = "Strong"
    if length < 12:
        strength_label = "Weak"
    elif length < 16:
        strength_label = "Moderate"

    console.print(Panel(
        f"[bold]Generated Password:[/] {password}\n"
        f"[bold]Strength:[/] {strength_label}\n"
        f"[bold]Length:[/] {length}\n"
        f"[bold]Symbols Included:[/] {'No' if no_symbols else 'Yes'}",
        title="Password Generator",
        border_style="cyan"
    ))
