#!/usr/bin/python3

import argparse
import logging
import os
from queue import Empty
import subprocess
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
from itertools import cycle  # For cycling through styles


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

    # Extended style list for more color variety (at least 12 now)
    styles = cycle(
        [
            Style(color="bright_blue"),
            Style(color="yellow"),
            Style(color="magenta"),
            Style(color="bright_green"),
            Style(color="bright_cyan"),
            Style(color="red"),
            Style(color="bright_magenta"),
            Style(color="bright_yellow"),
            Style(color="dark_orange"),  # Use "dark_orange" (or "orange1")
            Style(color="sea_green2"),
            Style(color="medium_purple1"),
            Style(color="light_goldenrod1"),
            Style(color="deep_sky_blue2"),  # additional color
            Style(color="orange3"),  # Use orange3 (or other orange variants)
            Style(color="orchid1"),  # Orchid
            Style(color="pale_green1"),  # Pale Green
        ]
    )

    try:
        tool = Tool(interface=args.interface, greet=True)

        if args.target:
            try:
                target_ip = args.target
                gateway_ip = tool.get_gateway_ip()
                target_mac = tool._get_mac(target_ip)
                gateway_mac = tool._get_mac(gateway_ip)

                if args.scapyforwarding:
                    tool.target_ip = target_ip
                    tool.target_mac = target_mac
                    tool.gateway_mac = gateway_mac
                    tool.use_scapy_forwarding = True

                    tool.start_sniffer()
                    console.print(
                        f"[bold green]Traffic rerouting started (Scapy). Press Ctrl+C to stop.[/]"
                    )
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        tool.stop_sniffer()
                        tool._restore_arp()
                        console.print(
                            "[bold yellow]Traffic rerouting stopped. ARP table restored.[/]"
                        )
                else:  # Use system IP forwarding (iptables/sysctl)
                    try:
                        subprocess.run(
                            ["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True
                        )
                        subprocess.run(
                            [
                                "iptables",
                                "-t",
                                "nat",
                                "-A",
                                "PREROUTING",
                                "-p",
                                "tcp",
                                "--destination-port",
                                "80",
                                "-j",
                                "REDIRECT",
                                "--to-ports",
                                "8080",
                            ],
                            check=True,
                        )
                        console.print(
                            f"[bold green]Traffic rerouting started (sysctl/iptables).[/]"
                        )
                        console.print(
                            f"[bold yellow]Remember to disable forwarding and clear iptables rules when done using 'sysctl -w net.ipv4.ip_forward=0' and 'iptables -F -t nat'.[/]"
                        )

                    except subprocess.CalledProcessError as e:
                        console.print(
                            f"[bold red]Error setting up forwarding: {e}\nCheck if you have sudo/root privileges.[/]"
                        )
                        sys.exit(1)

            except AddressResolutionError as e:
                console.print(f"[bold red]ARP Resolution Error: {e}[/]")
                sys.exit(1)

        elif args.send_info_packet:
            try:
                tool.send_info_packet(args.send_info_packet, use_udp=not args.raw)
                console.print(
                    f"[bold green]Information packet sent to: {args.send_info_packet}[/]"
                )
                tool.pretty_print_replies()  # Process replies
            except (
                PacketSendError,
                PacketReceiveError,
                AddressResolutionError,
                PacketProcessingError,
            ) as e:
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
                netinfo_table = Table(title="Network Information", style="bold cyan")
                netinfo_table.add_column("Property", justify="right")
                netinfo_table.add_column("Value")  # No predefined style here

                for property_name, value in [
                    ("Interface:", tool.get_interface()),
                    ("Gateway IP:", tool.get_gateway_ip()),
                    ("Your IP:", tool.get_own_ip()),
                    ("Your MAC:", tool.get_own_mac()),
                ]:
                    current_style = next(styles)  # Get the next style from the cycle

                    netinfo_table.add_row(
                        Text(property_name, style=current_style),
                        Text(
                            value, style=current_style
                        ),  # Use the same style for the value
                    )

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

                # netinfo_table.add_row(
                #     Text("Interface:", style=styles[0]),
                #     Text(tool.get_interface(), style=styles[1]),
                # )
                # netinfo_table.add_row(
                #     Text("Gateway IP:", style=styles[2]),
                #     Text(tool.get_gateway_ip(), style=styles[3]),
                # )
                # netinfo_table.add_row(
                #     Text("Your IP:", style=styles[4]),
                #     Text(tool.get_own_ip(), style=styles[5]),
                # )
                # netinfo_table.add_row(
                #     Text("Your MAC:", style=styles[6]),
                #     Text(tool.get_own_mac(), style=styles[7]),
                # )

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
