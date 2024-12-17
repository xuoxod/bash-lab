#!/usr/bin/python3

import os
import getpass
import logging
import socket  # Import socket for protocol constants
import netifaces
from scapy.all import *
from scapy.all import Ether, IP, UDP, TCP, ICMP, raw
from .prettyprinter import PrettyPrinter as pp  # Assuming definition elsewhere
from networkexceptions import NoIPError, DefaultInterfaceNotFoundError
from .packetutils import PacketUtils

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class PacketMaker:
    def __init__(
        self,
        own_ip,
        own_mac,
        current_user,
        os_info,
        kernel_version,
        cpu_info,
        interface=None,
    ):
        self.interface = interface
        self.interface_ip = own_ip
        self.interface_mac = own_mac
        self.pretty_printer = pp()
        self.packet_utils = PacketUtils()  # Instantiate PacketUtils
        self.current_user = current_user
        self.os_info = os_info
        self.kernel_version = kernel_version
        self.cpu_info = cpu_info

    def craft_udp_packet(
        self,
        dst_ip,
        src_port=None,
        dst_port=None,
        payload="Test UDP Packet",
        marker=None,
    ):
        src_ip = self.interface_ip

        if not src_ip:
            raise NoIPError("Could not determine source IP address.")

        if src_port is None:
            src_port = RandShort()

        if marker:
            payload = marker + (
                payload or ""
            )  # or marker + bytes(payload) if you intend to use bytes
        elif payload is None:
            payload = (
                "Default TCP Payload"  # or b"Default TCP Payload" to directly use bytes
            )

        ip_header = self.packet_utils.craft_ip_header(
            src_ip, dst_ip, socket.IPPROTO_UDP
        )

        packet = (
            Ether(src=self.interface_mac, dst="ff:ff:ff:ff:ff:ff")
            / ip_header
            / UDP(sport=src_port, dport=dst_port)
            / raw(payload)
        )

        return packet

    def craft_tcp_packet(
        self,
        dst_ip,
        src_port=None,
        dst_port=None,
        flags="S",
        payload="Test TCP Packet",
        marker=None,
    ):
        if src_port is None:
            src_port = RandShort()

        if marker:
            payload = marker + (
                payload or ""
            )  # or marker + bytes(payload) if you intend to use bytes
        elif payload is None:
            payload = (
                "Default TCP Payload"  # or b"Default TCP Payload" to directly use bytes
            )

        ip_header = self.packet_utils.craft_ip_header(self.interface_ip, dst_ip)
        tcp_header = TCP(sport=src_port, dport=dst_port, flags=flags)

        packet = ip_header / tcp_header / raw(payload.encode())

        return packet

    def craft_icmp_packet(
        self, dst_ip, type=8, code=0, payload="Test ICMP Packet", marker=None
    ):
        src_ip = self.interface_ip

        if not src_ip:
            raise NoIPError("Could not determine source IP address.")

        if marker:
            payload = marker + (
                payload or ""
            )  # or marker + bytes(payload) if you intend to use bytes
        elif payload is None:
            payload = (
                "Default TCP Payload"  # or b"Default TCP Payload" to directly use bytes
            )

        ip_header = self.packet_utils.craft_ip_header(
            src_ip, dst_ip, socket.IPPROTO_ICMP
        )

        packet = (
            Ether(src=self.interface_mac, dst="ff:ff:ff:ff:ff:ff")
            / ip_header
            / ICMP(type=type, code=code)
            / raw(payload)
        )
        return packet

    def _get_default_interface(self):
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][1]
        except (KeyError, IndexError):  # Catch all possible lookup errors
            return None  # Return None. Let the constructor handle it.

    def print_system_info(self):
        if not self.interface:
            self.interface = self._get_default_interface()
            if not self.interface:
                raise DefaultInterfaceNotFoundError("No valid network interface found.")

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
        self.pretty_printer.print_table_2("System Information", data)
