#!/usr/bin/python3

import argparse
import logging
import os
from queue import Empty
import sys
import time

from rich.console import Console
from rich.table import Table
from rich.markdown import Markdown
from rich.panel import Panel
from rich.text import Text
from rich.style import Style
from rich.logging import RichHandler
from tool import Tool  # Import your Tool class
from networkexceptions import (
    PacketReceiveError,
    PacketSendError,
    AddressResolutionError,
    DefaultInterfaceNotFoundError,
    InterfaceConfigurationError,
    NetworkError,
    PacketProcessingError,
)


# Configure Rich logging
logging.basicConfig(
    level="INFO",
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)],
)

log = logging.getLogger("rich")


def main():
    console = Console()

    # Rich-formatted description (Markdown)
    description_md = """
    # Network Tool Interface

    This script provides a console interface for the `Tool` class, allowing you to interact with various network functionalities. You can display network information, send custom information packets, or perform traffic rerouting.
    """
    console.print(Markdown(description_md))

    parser = argparse.ArgumentParser(
        description="Network Tool Interface",
        epilog="""
        Examples:
            Display network info (default): ./run.py 
            Send info packet (UDP):        ./run.py -sip 192.168.1.105
            Send info packet (raw IP):     ./run.py -sip 192.168.1.105 --raw
            Reroute traffic (sysctl):     ./run.py -t 192.168.1.105
            Reroute traffic (Scapy):      ./run.py -t 192.168.1.105 -sf
            Specify interface:           ./run.py -i eth0 -t 192.168.1.105 -sf
            Display network info only:    ./run.py --netinfo
        """,  # Multi-line epilog with enhanced examples
        formatter_class=argparse.RawDescriptionHelpFormatter,  # Preserve formatting
    )

    parser.add_argument(
        "-i", "--interface", help="Specify the network interface (e.g., eth0, wlan0)"
    )

    group = parser.add_mutually_exclusive_group()  # Mutually exclusive options

    # target argument -t or --target
    # metavar: "TARGET_IP"
    group.add_argument(
        "-t",
        "--target",  # For traffic rerouting
        metavar="TARGET_IP",
        help="Target IP address for traffic rerouting",
    )

    # send custom info packet -sip or --send-info-packet
    # metavar: "DEST_IP"
    group.add_argument(
        "-sip",
        "--send-info-packet",  # For sending info packets
        metavar="DEST_IP",
        help="Destination IP address for sending information packet",
    )

    # netinfo argument -ni or --netinfo
    # action: store_true
    group.add_argument(
        "-ni", "--netinfo", action="store_true", help="Display network information only"
    )  # Explicitly for network info

    # scapyforwarding argument -sf or --scapyforwarding
    # action: store_true
    parser.add_argument(
        "-sf",
        "--scapyforwarding",
        action="store_true",
        help="Use Scapy for IP forwarding (default: sysctl)",
    )

    # raw argument -r or --raw
    # action: store_true
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Send information packet using raw IP (default: UDP)",
    )

    # Parse arguments
    args = parser.parse_args()

    # try block:
    try:
        tool = Tool(interface=args.interface, greet=True)

        if args.target:  # Traffic rerouting mode (add actual logic here)
            console.print("[yellow]Traffic rerouting is not yet implemented.[/]")
            # ... (Add your traffic rerouting code here using the 'tool' object)

        elif args.send_info_packet:  # Send info packet mode
            try:
                tool.send_info_packet(args.send_info_packet, use_udp=not args.raw)
                console.print(
                    f"[bold green]Information packet sent to: {args.send_info_packet}[/]"
                )
                tool.pretty_print_replies()  # Process any replies
            except (
                PacketSendError,
                PacketReceiveError,
                AddressResolutionError,
                PacketProcessingError,
            ) as e:  # Handles from tool
                console.print(f"[bold red]{e}[/]")
                sys.exit(1)

        elif args.netinfo or (
            not any([args.target, args.send_info_packet, args.netinfo])
        ):
            if not tool.is_network_info_available():
                console.print(
                    "[bold red]Network information not available. Check your interface or run initialization.[/]"
                )  # Informative error message
                sys.exit(1)

            else:
                # Display the information if available.
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

    except (DefaultInterfaceNotFoundError, InterfaceConfigurationError) as dinfe:
        console.print(
            f"[bold red]Interface Error: {dinfe}[/]\n\n"
        )  # Specific interface errors
        sys.exit(1)

    except NetworkError as ne:  # Catch any other NetworkError
        console.print(f"[bold red]Network Error: {ne}[/]\n\n")
        sys.exit(1)

    except (
        Exception
    ) as e:  # Catch any other unexpected exceptions (non-network related)
        console.print_exception(f"General exception: {e}\n")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
