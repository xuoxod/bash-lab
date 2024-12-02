#!/usr/bin/python3

import os
import getpass
import netifaces
import logging
import subprocess  # For subprocess.run()
import threading  # For threading.Thread and threading.Lock
import time  # For time.sleep()
import errno  # For errno (used for error checking in threads)
import queue
import rich

from scapy.all import *  #  Import all of Scapy
from scapy.all import IP, Ether, ARP, UDP, TCP, ICMP, sr1
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.pretty import Pretty
from textcolors import TextColors
from queue import Queue, Empty
from networkexceptions import *
from helpers.netutil import NetUtil as netutil

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class PrettyPrinter:
    def __init__(self):
        self.console = Console()

    def print_packet(self, packet):
        if packet:
            self.console.print(
                Panel(str(packet.summary()), title="Packet Reply", border_style="green")
            )
        else:
            self.console.print("[bold yellow]No packet to display[/]")

    def print_table_1(
        self, title, data, style="bold white"
    ):  # Generalized table print.
        table = Table(
            title=title, style=style, show_header=True, header_style="bold magenta"
        )

        # Auto-detect column alignment based on data type
        alignments = []
        for item in data[0]:  # Check the first row (assuming it's header)
            if all(isinstance(x, (int, float)) for x in [row[0] for row in data]):
                alignments.append("right")  # Align numbers right
            else:
                alignments.append("left")  # Align text left

        for i, header in enumerate(data[0]):  # Add columns with alignment.
            table.add_column(header, justify=alignments[i])

        for row in data[1:]:
            table.add_row(*[str(x) for x in row])  # Ensure all data is string.

        self.console.print(table)

    def print_table_2(self, title, data, style="bold white"):
        console_width = self.console.width  # Get current console width
        table = Table(
            title=title,
            style=style,
            show_header=True,
            header_style="bold magenta",
            width=int(
                console_width * 0.8
            ),  # Use 80% of console width (adjust as needed)
            box=rich.box.ROUNDED,  # Nicer looking box
            show_lines=True,  # Add lines between rows for clarity
        )

        # Add columns dynamically based on the header row
        for header in data[0]:
            table.add_column(header)  # Add columns

        # Add rows (excluding the header)
        for row in data[1:]:
            table.add_row(*row)  # Add rows to the table.

        self.console.print(table)

    def print_system_info(self, system_info):  # Example custom info printing
        """Prints aligned system info using Columns."""
        panels = []
        for key, value in system_info.items():  # Create panels for each info
            text = Text(f"{key}: {value}")

            panels.append(
                Panel(
                    Align(text, align="left", vertical="middle"),
                    border_style="green",
                    expand=True,
                )
            )

        self.console.print(Columns(panels, padding=(1, 1)))

    def pprint(
        self, data, title=None, expand=True, style="white"
    ):  # New general pretty print method.
        """Pretty prints arbitrary data with an optional title."""
        pretty_data = Pretty(data)
        if title:
            panel = Panel(
                pretty_data,
                title=title,
                border_style="blue",
                expand=expand,
                style=style,
            )
            self.console.print(panel)

        else:  # Print pretty data without a panel
            self.console.print(pretty_data)
