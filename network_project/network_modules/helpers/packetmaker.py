#!/usr/bin/python3

import os
import getpass
import netifaces
import socket
import logging
from scapy.all import *
from scapy.all import IP, Ether, ARP, UDP, TCP, ICMP, sr1, RandShort
from helpers.prettyprinter import PrettyPrinter as pp
from networkexceptions import *
from helpers.netutil import NetUtil

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class PacketMaker:
    def __init__(self, interface=None):
        self.interface = interface
        self.netutil = NetUtil(interface)  # Use NetUtil for network functions
        self.pretty_printer = pp()
        self._get_system_info()  # Call in constructor

    def _get_system_info(self):
        self.current_user = getpass.getuser()
        self.os_info = f"{os.name} {os.uname().release}"
        self.kernel_version = os.uname().version
        self.cpu_info = f"{os.uname().machine} ({os.cpu_count()} cores)"

        if not self.interface:
            self.interface = self.netutil.get_default_interface()

        self.interface_ip = self.netutil.get_own_ip()
        self.interface_mac = self.netutil.get_own_mac()

        if not self.interface:
            raise InterfaceError("No valid network interface found.")

    def craft_udp_packet(
        self,
        dst_ip="127.0.0.1",
        src_port=30660,
        dst_port=30770,
        payload="Test UDP Packet",
        marker=None,
    ):
        src_ip = self.netutil.get_own_ip()  # Use netutil for IP retrieval
        if not src_ip:
            raise NoIPError(
                "Could not determine source IP address."
            )  # Raise custom exception

        if src_port is None:
            src_port = RandShort()

        if marker:
            payload = marker + payload

        packet = (
            Ether(src=self.interface_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src=src_ip, dst=dst_ip)
            / UDP(sport=src_port, dport=dst_port)
            / payload
        )
        return packet

    def craft_tcp_packet(
        self,
        dst_ip="127.0.0.1",
        src_port=None,
        dst_port=66667,
        flags="S",
        payload="Test TCP Packet",
        marker=None,
    ):
        src_ip = self.netutil.get_own_ip()  # Use netutil for IP retrieval

        if not src_ip:
            raise NoIPError(
                "Could not determine source IP address."
            )  # Raise custom exception

        if src_port is None:
            src_port = RandShort()

        if marker:
            payload = marker + payload

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=src_port, dport=dst_port, flags=flags)
            / payload
        )
        return packet

    def craft_icmp_packet(
        self,
        dst_ip="127.0.0.1",
        type=8,
        code=0,
        payload="Test ICMP Packet",
        marker=None,
    ):
        src_ip = self.netutil.get_own_ip()  # Use netutil for IP retrieval
        if not src_ip:
            raise NoIPError(
                "Could not determine source IP address."
            )  # Raise custom exception

        if marker:
            payload = marker + payload

        packet = (
            Ether(src=self.interface_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src=src_ip, dst=dst_ip)
            / ICMP(type=type, code=code)
            / payload
        )
        return packet

    def print_system_info(self):
        data = [
            ["Property", "Value"],
            ["Interface", self.interface],
            ["Interface IP", self.interface_ip],
            ["Interface MAC", self.interface_mac],
            ["Current User", self.current_user],
            ["OS Info", self.os_info],
            ["Kernel Version", self.kernel_version],
            ["CPU Info", self.cpu_info],
        ]
        self.pretty_printer.print_table_2(
            "System Information", data
        )  # Use print_table_2
