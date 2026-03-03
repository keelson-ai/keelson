"""ASCII banner for Pentis."""

from rich.console import Console
from rich.text import Text

from pentis import __version__

BANNER = r"""
    ____  _____ _   _ _____ ___ ____
   |  _ \| ____| \ | |_   _|_ _/ ___|
   | |_) |  _| |  \| | | |  | |\___ \
   |  __/| |___| |\  | | |  | | ___) |
   |_|   |_____|_| \_| |_| |___|____/
"""


def print_banner() -> None:
    console = Console()
    text = Text(BANNER, style="bold red")
    console.print(text)
    console.print(f"  [dim]AI Agent Security Scanner v{__version__}[/dim]")
    console.print()
