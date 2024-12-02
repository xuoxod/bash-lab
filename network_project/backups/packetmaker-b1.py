#!/usr/bin/python3

import os
import platform
import getpass
import netifaces
import socket
import logging

from scapy.all import *
from scapy.all import IP, Ether, ARP, UDP, TCP, ICMP
from networkexceptions import *
from helpers.prettyprinter import PrettyPrinter as prettyprinter


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class PacketMaker:

    def __init__(self, interface=None):
        # 1. Network Interface Resolution
        self.interface = interface or self._get_default_interface()
        if not self.interface:
            raise ValueError("No valid network interface found.")

        # Store interface IP and MAC
        self.interface_ip = self._get_own_ip()
        self.interface_mac = self._get_own_mac()

        # Pretty print
        self.pretty_printer = prettyprinter()

        # 2. System Information
        self.current_user = getpass.getuser()
        self.os_name = platform.system()
        self.os_version = platform.release()  # Concise version
        self.kernel_version = platform.version()
        self.cpu_info = platform.processor()

    #   Builtin class features
    def _get_default_interface(self):
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][1]
        except KeyError:
            return None

    def _get_own_ip(self):
        try:
            return netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]["addr"]
        except (KeyError, IndexError):
            return None

    def _get_own_mac(self):
        try:
            return netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]["addr"]
        except (KeyError, IndexError):
            return None

    #   Packet creation methods
    def craft_udp_packet(
        self,
        src_ip=None,
        dst_ip="127.0.0.1",
        src_port=55555,
        dst_port=55556,
        payload="Test UDP Packet",
        marker=None,
    ):
        if src_ip is None:
            try:  # Get the default IP of current network interface if available.
                src_ip = get_if_addr(conf.iface)  # Use Scapy's interface configuration
            except Exception as e:  # Handle potential errors (e.g. no default route).
                print(f"Error getting source IP: {e}")
                src_ip = ""  # Return an empty string if no IP available.

        if marker:  # Include the marker at the beginning of the payload if provided.
            payload = marker + payload

        packet = (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=src_port, dport=dst_port)
            / payload
        )

        return packet

    def craft_tcp_packet(
        self,
        src_ip=None,
        dst_ip="127.0.0.1",
        src_port=66666,
        dst_port=66667,
        flags="S",
        payload="Test TCP Packet",
        marker=None,
    ):  # Example TCP packet.
        if src_ip is None:
            try:
                src_ip = get_if_addr(conf.iface)
            except Exception as e:
                print(f"Error getting source IP: {e}")
                src_ip = ""

        if marker:  # If a marker is specified, prepend it to the payload.
            payload = marker + payload

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=src_port, dport=dst_port, flags=flags)
            / payload
        )

        return packet

    def craft_icmp_packet(
        self,
        src_ip=None,
        dst_ip="127.0.0.1",
        type=8,
        code=0,
        payload="Test ICMP Packet",
        marker=None,
    ):  # Example ICMP packet.
        if src_ip is None:  # Assign a source IP based on default route, if available.
            try:
                src_ip = get_if_addr(conf.iface)
            except Exception as e:  # Print an error if there's a problem.
                print(f"Error getting source IP: {e}")
                src_ip = ""  # Or use other default/handling for src_ip.

        if marker:
            payload = marker + payload  # Prepend marker to payload if given.

        packet = (
            Ether() / IP(src=src_ip, dst=dst_ip) / ICMP(type=type, code=code) / payload
        )
        return packet

    # Add methods for other protocols (ICMP, etc.) or more specialized packet crafting as needed.

    #   Pretty printing

    def _print_system_info(self):
        """Prints the gathered system information during init."""
        print(f"Interface: {self.interface}")
        print(f"Interface IP: {self.interface_ip}")
        print(f"Interface MAC: {self.interface_mac}")
        print(f"Current User: {self.current_user}")
        print(f"OS Name: {self.os_name}")
        print(f"OS Version: {self.os_version}")
        print(f"Kernel Version: {self.kernel_version}")
        print(f"CPU Info: {self.cpu_info}")
        print(f"CPU Capabilities: {self.cpu_capabilities}")

    def _print_system_info_rich(self):
        """Prints system info using the PrettyPrinter."""

        data = [
            ["Property", "Value"],  # Header row
            ["Interface", self.interface],
            ["Interface IP", self.interface_ip],
            ["Interface MAC", self.interface_mac],
            ["Current User", self.current_user],
            ["OS Name", self.os_name],
            ["OS Version", self.os_version],
            ["Kernel Version", self.kernel_version],
            ["CPU Info", self.cpu_info],
            ["CPU Capabilities", self.cpu_capabilities],
        ]

        self.prettyprinter.print_table(
            "System Information", data, style="bold cyan"
        )  # Using PrettyPrinter
