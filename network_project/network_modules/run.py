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
        description="Custom Librarys Interface",
        epilog="""
        Examples:
            Display network info (default): ./run.py 
            Reroute traffic using sysctl:  ./run.py -t 192.168.1.105
            Reroute traffic using Scapy:   ./run.py -t 192.168.1.105 -sf
            Specify interface:            ./run.py -i eth0 -t 192.168.1.105 -sf  
            Display network info only:   ./run.py --netinfo
        """,  # Multi-line epilog with enhanced examples
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
                netinfo_table = Table(title="Network Information", style="bold cyan")
                netinfo_table.add_column(
                    "Property", style="bold white", justify="right"
                )  # Right-align properties
                netinfo_table.add_column("Value", style="green")

                # Use Text and Style for finer color control:

                styles = [  # List of styles (at least 8, easily extendable)
                    Style(color="bright_blue"),
                    Style(color="yellow"),  # Added colors
                    Style(color="magenta"),
                    Style(color="bright_green"),
                    Style(color="bright_cyan"),
                    Style(color="red"),
                    Style(color="bright_magenta"),
                    Style(color="bright_yellow"),
                ]

                netinfo_table.add_row(
                    Text("Interface:", style=styles[0]),
                    Text(tool.get_interface(), style=styles[1]),
                )
                netinfo_table.add_row(
                    Text("Gateway IP:", style=styles[2]),
                    Text(tool.get_gateway_ip(), style=styles[3]),
                )
                netinfo_table.add_row(
                    Text("Your IP:", style=styles[4]),
                    Text(tool.get_own_ip(), style=styles[5]),
                )
                netinfo_table.add_row(
                    Text("Your MAC:", style=styles[6]),
                    Text(tool.get_own_mac(), style=styles[7]),
                )

                console.print(Panel.fit(netinfo_table))

    except Exception as e:  # Catch any other unexpected exceptions

        console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
