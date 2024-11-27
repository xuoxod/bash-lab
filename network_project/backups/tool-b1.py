#!/usr/bin/python3
import os
import getpass
import netifaces
import argparse
import time
import multiprocessing  # Import for process management
import logging

from scapy.all import *
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Assuming TextColors is in a separate file (e.g., textcolors.py)
from textcolors import TextColors  # Import the TextColors class

# Assuming sniffer is in a separate file (sniffer.py), import necessary classes
from sniffer import Sniffer


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class Tool:
    def __init__(self, interface=None, greet=False):
        self.console = Console()
        self._interface = interface
        self.greet = greet

        # Initialize network info attributes to None.  They'll be populated by initialize()
        self._gateway_ip = None
        self._own_ip = None
        self._own_mac = None
        # self._gateway_ip = self._get_default_gateway()
        # self._own_ip = self._get_own_ip()
        # self._own_mac = self._get_own_mac()

        if greet:
            self.greet_user()

    def initialize(self):
        """Retrieves and stores network information."""
        self._interface = self._interface or self._get_default_interface()

        if (
            self._interface is None
        ):  # Handle the case where no default interface is found
            self.console.print(
                f"{TextColors.FAIL}Error: No suitable network interface found.{TextColors.ENDC}",
                style="bold red",
            )
            return  # Or raise an exception if that's your preferred error handling

        self._gateway_ip = self._get_default_gateway()
        self._own_ip = self._get_own_ip()
        self._own_mac = self._get_own_mac()

        if self._gateway_ip is None or self._own_ip is None or self._own_mac is None:
            self.console.print(
                f"{TextColors.WARNING}Warning: Some network information could not be retrieved.{TextColors.ENDC}",
                style="bold yellow",  # Use yellow for warnings
            )

    def greet_user(self):  # Remains the same
        """Presents a colorful greeting to the user."""
        username = getpass.getuser()
        greeting_table = Table(
            title=f"Welcome, {username}!", show_header=True, style="bold cyan"
        )
        greeting_table.add_row("This is the Tool, your network assistant.")
        greeting_table.add_row(f"Interface: {self._interface}")
        greeting_table.add_row(f"Gateway IP: {self._gateway_ip}")
        greeting_table.add_row(f"Own IP: {self._own_ip}")
        greeting_table.add_row(f"Own MAC: {self._own_mac}")

        self.console.print(Panel(greeting_table, border_style="green", expand=False))

    def refresh_network_info(self):
        """Refreshes the stored network information."""
        self.initialize()  # Simply call initialize to refresh

    def is_network_info_available(self):
        """Checks if the required network information (interface, gateway, own IP) is available."""
        return (
            self._interface is not None
            and self._gateway_ip is not None
            and self._own_ip is not None
            and self._own_mac is not None
        )

    def _exit_prog(self):
        sys.exit(0)

    def _get_default_interface(self):
        """Gets the default network interface."""
        try:
            gws = netifaces.gateways()
            default_gateway = gws["default"][netifaces.AF_INET]
            return default_gateway[1]
        except (KeyError, IndexError):
            self.console.print(
                f"{TextColors.FAIL}Error: Could not determine default interface.{TextColors.ENDC}",
                style="bold red",
            )
            return None

    def _get_default_gateway(self):
        """Gets the IP of the default gateway."""
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][0]
        except (KeyError, IndexError):
            self.console.print(
                f"{TextColors.FAIL}Error: Could not determine default gateway.{TextColors.ENDC}",
                style="bold red",
            )
            return None

    def _get_own_ip(self):
        """Gets the IP address of the current machine."""
        try:
            return netifaces.ifaddresses(self._interface)[netifaces.AF_INET][0]["addr"]
        except (ValueError, KeyError, IndexError, AttributeError):
            self.console.print(
                f"{TextColors.FAIL}Error: Could not get own IP address.{TextColors.ENDC}",
                style="bold red",
            )
            return None

    def _get_own_mac(self):
        """Gets the MAC address of the current machine."""
        try:
            return get_if_hwaddr(self._interface)
        except OSError:
            self.console.print(
                f"{TextColors.FAIL}Error: Could not get own MAC address.{TextColors.ENDC}",
                style="bold red",
            )
            return None

    def get_interface(self):  # Keep interface getter
        return self._interface

    def get_gateway_ip(self):  # Keep gateway getter
        return self._gateway_ip

    def get_own_ip(self):
        return self._own_ip

    def get_own_mac(self):
        return self._own_mac
