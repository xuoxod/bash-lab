#!/usr/bin/python3

import os
import sys
import argparse
import ipaddress
import json
import csv
import logging
import random
import scapy.all as scapy

from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.style import Style
from rich.text import Text

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# ... (TextColors class remains the same, but we'll use Rich styles instead)

console = Console()  # Create a Rich console object


class NetRecon:
    # ... (Existing NetRecon class code)
    pass


def print_help(parser, command=None):  # Helper function to print colorful help
    """Prints colorful help message using Rich."""
    help_text = parser.format_help()  # Get the default help text

    # Custom styles for different parts of the help message (using Rich styles)
    title_style = Style(color="bright_magenta", bold=True)
    description_style = Style(color="cyan")
    argument_style = Style(color="green")
    option_style = Style(color="yellow")
    example_style = Style(color="bright_blue")

    text = Text.from_markup(help_text)

    # Apply styles to specific parts using slicing and regular expressions.
    # ... (Apply styles to section headers, option text etc., similar to previous responses).

    console.print(
        Panel(text, title=f"[bold bright_cyan]{parser.prog}[/]", border_style="dim")
    )


def main():
    parser = argparse.ArgumentParser(
        prog="netrecon",
        description="NetRecon: Your Swiss Army knife for network analysis.",
        epilog="Example: netrecon scan -n 192.168.1.0/24 -o results.json -f json",
        formatter_class=argparse.RawDescriptionHelpFormatter,  # For multi-line descriptions,
        add_help=False,  # Disable default help to use custom help.
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- scan subcommand ---
    # ... (scan subcommand code remains the same)

    # --- other subcommands (add as needed) ---

    args, unknown_args = parser.parse_known_args()  # Get unknown args

    if (
        unknown_args and unknown_args[0].lower() == "help"
    ):  # Check for 'help' after command
        if args.command:  # Check for a subcommand before 'help'
            # Get the subparser for the command and print its help
            subparser = subparsers.choices[args.command]
            print_help(subparser)  # Pass the subparser to colorful help
        else:
            print_help(parser)  # Prints the main help if not called for subcommand.
        sys.exit(0)

    if not args.command:
        print_help(parser)
        sys.exit(0)

    net_recon = NetRecon()

    if args.command == "scan":
        # ... (scan command logic remains the same)
        pass

    # Handle other subcommands


if __name__ == "__main__":
    main()
