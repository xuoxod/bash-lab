#!/usr/bin/python3

import argparse
import logging
import os
import sys

from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text
from rich.style import Style
from rich.logging import RichHandler

from tool import Tool  # Import your Tool class

# Configure Rich logging
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)],  # Rich traceback formatting
)

log = logging.getLogger("rich")


def main():

    parser = argparse.ArgumentParser(
        description="Network Tool Interface",
        epilog="Example: python run.py -t 192.168.1.105 -sf",  # Example in epilog
        formatter_class=argparse.RawDescriptionHelpFormatter,  # Preserve formatting
    )

    parser.add_argument(
        "-i", "--interface", help="Specify the network interface (e.g., eth0, wlan0)"
    )

    group = parser.add_mutually_exclusive_group()  # Mutually exclusive reroute/info

    group.add_argument(
        "-t",
        "--target",
        metavar="TARGET_IP",
        help="Target IP address for traffic rerouting",
    )
    group.add_argument(
        "-ni", "--netinfo", action="store_true", help="Display network information"
    )

    parser.add_argument(
        "-sf",
        "--scapyforwarding",
        action="store_true",
        help="Use Scapy for IP forwarding (default: sysctl)",
    )  # Forwarding option

    console = Console()

    # Rich-formatted description (Markdown)
    description_md = """
    # Network Tool Interface

    This script provides a console interface for the `Tool` class, allowing you to interact with network functionalities.  You can either display network information or perform traffic rerouting to a specified target IP.
    """
    console.print(Markdown(description_md))

    args = parser.parse_args()

    try:

        tool = Tool(
            interface=args.interface,
            greet=True,
            use_scapy_forwarding=args.scapyforwarding,
        )  # Initialize your Tool

        if args.target:  # Rerouting mode
            try:
                tool.start_rerouting(args.target)  # Start rerouting
                console.print(
                    f"[bold green]Traffic rerouting started for target: {args.target}[/]"
                )
                try:
                    while (
                        True
                    ):  # Keep the main thread alive (can add interactive commands here later)
                        time.sleep(1)

                except KeyboardInterrupt:  # Exit gracefully on Ctrl+C
                    print("\nStopping rerouting...")  # Indicate rerouting is stopping

                    tool.stop_rerouting()
                    console.print(
                        "[bold green]Traffic rerouting stopped and ARP table restored.[/]"
                    )  # Positive message

            except (
                ValueError
            ) as e:  # Handle MAC address resolution failure specifically

                console.print(f"[bold red]Error: {e}[/]")
                sys.exit(1)  # Indicate an error to the user

            except (
                Exception
            ) as e:  # Log or print other unexpected exceptions during rerouting

                console.print(
                    f"[bold red]Error during rerouting: {e}[/]"
                )  # Rich error message
                sys.exit(1)  # Non-zero exit code indicates error

        elif args.netinfo or (
            not args.netinfo and not args.target
        ):  # Network info mode (default)

            # ... existing Network Info display logic

            if not tool.is_network_info_available():
                console.print(
                    "[bold red]Network information not available. Check your interface or run initialization.[/]"
                )  # Informative error message
                sys.exit(1)
            else:  # Display the information if available.

                netinfo_table = Table(
                    title="Network Information", style="bold cyan"
                )  # Rich table
                netinfo_table.add_column(
                    "Property", style="bold white"
                )  # Style columns
                netinfo_table.add_column("Value", style="green")

                netinfo_table.add_row("Interface", tool.get_interface())  # Rich table
                netinfo_table.add_row("Gateway IP", tool.get_gateway_ip())
                netinfo_table.add_row("Your IP", tool.get_own_ip())
                netinfo_table.add_row("Your MAC", tool.get_own_mac())

                console.print(Panel.fit(netinfo_table))

    except Exception as e:  # Catch any other unexpected exceptions

        console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
