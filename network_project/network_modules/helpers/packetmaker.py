#!/usr/bin/python3

import os
import getpass
import logging
import socket  # Import socket for protocol constants
from scapy.all import *
from .prettyprinter import PrettyPrinter as pp  # Assuming definition elsewhere
from networkexceptions import NoIPError
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
            payload = marker + payload

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
            payload = marker + payload

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

    def ack_scan(self, dst_ip, ports, verbose=0):
        ans, unans = sr(
            IP(dst=dst_ip) / TCP(dport=ports, flags="A"), timeout=2, verbose=verbose
        )

        unfiltered_ports = []
        filtered_ports = []

        for sent, received in ans:
            if sent[TCP].dport == received[TCP].sport:
                unfiltered_ports.append(sent[TCP].dport)

        for sent in unans:
            filtered_ports.append(sent[TCP].dport)

        results = {
            "Unfiltered Ports": unfiltered_ports,
            "Filtered Ports": filtered_ports,
        }
        self.pretty_printer.pprint(
            results, title="ACK Scan Results", style="bold yellow"
        )

        return unfiltered_ports, filtered_ports  # Return both lists

    def xmas_scan(self, dst_ip, ports, verbose=0):
        ans, unans = sr(
            IP(dst=dst_ip) / TCP(dport=ports, flags="FPU"), timeout=2, verbose=verbose
        )

        closed_ports = []
        for sent, received in ans:
            if received.haslayer(TCP) and received[TCP].flags == "RA":
                closed_ports.append(sent.dport)

        for sent in unans:  # Include unanswered packets
            closed_ports.append(sent.dport)  # Indicate potentially filtered

        results = {"Closed/Filtered Ports": closed_ports}  # Show closed/filtered
        self.pretty_printer.pprint(
            results, title="Xmas Scan Results", style="bold red"
        )  # Update message
        return closed_ports  # Return the identified ports

    def ip_scan(self, dst_ip, verbose=0):
        ans, unans = sr(
            IP(dst=dst_ip, proto=(0, 255)) / "SCAPY",
            retry=2,
            timeout=2,
            verbose=verbose,
        )
        supported_protocols = []
        for sent, received in ans:
            supported_protocols.append(sent.proto)
        results = {"Supported Protocols": supported_protocols}
        self.pretty_printer.pprint(results, title="IP Scan Results", style="bold blue")
        return supported_protocols

    def arp_ping(self, target_network, verbose=0):
        ans, unans = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_network),
            timeout=2,
            verbose=verbose,
        )
        live_hosts = []
        for sent, received in ans:
            live_hosts.append((received.psrc, received.hwsrc))

        results = {"Live Hosts": live_hosts}
        self.pretty_printer.pprint(
            results, title="ARP Ping Results", style="bold magenta"
        )
        return live_hosts

    def icmp_ping(self, target_network, verbose=0):  # Updated name
        ans, unans = sr(IP(dst=target_network) / ICMP(), timeout=2, verbose=verbose)
        live_hosts = []
        for sent, received in ans:
            live_hosts.append(received.src)

        results = {"Live Hosts": live_hosts}
        self.pretty_printer.pprint(
            results, title="ICMP Ping Results", style="bold green"  # Updated title
        )
        return live_hosts

    def tcp_ping(self, target_network, dport=80, verbose=0):  # Renamed to tcp_ping
        ans, unans = sr(
            IP(dst=target_network) / TCP(dport=dport, flags="S"),
            timeout=2,
            verbose=verbose,
        )
        live_hosts = []
        for sent, received in ans:
            live_hosts.append(received.src)

        results = {"Live Hosts": live_hosts}
        self.pretty_printer.pprint(
            results, title="TCP Ping Results", style="bold cyan"
        )  # Updated title and style
        return live_hosts  # Return live hosts

    def udp_ping(self, target_network, dport=0, verbose=0):  # Renamed to udp_ping
        ans, unans = sr(
            IP(dst=target_network) / UDP(dport=dport), timeout=2, verbose=verbose
        )
        live_hosts = []
        for sent, received in ans:
            if received.haslayer(ICMP) and received[ICMP].type == 3:
                live_hosts.append(received.src)  # Store source IP of ICMP unreachable
            elif received.haslayer(UDP):  # Check for direct UDP replies as well
                live_hosts.append(received.src)

        results = {"Live Hosts": live_hosts}
        self.pretty_printer.pprint(
            results,
            title="UDP Ping Results",
            style="bold yellow",  # Updated title and style
        )

        return live_hosts

    def dns_request(self, target_dns, domain, record_type="A", verbose=0):
        ans = sr1(
            IP(dst=target_dns)
            / UDP(sport=RandShort(), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain, qtype=record_type)),
            timeout=2,
            verbose=verbose,
        )
        if ans:
            if record_type == "A":
                self.pretty_printer.pprint(
                    ans.an[0].rdata, title="DNS Request Results", style="bold green"
                )  # Correct title and style
                return ans.an[0].rdata
            elif record_type == "SOA":
                results = {
                    "mname": ans.an[0].mname,  # Corrected field names for SOA
                    "rname": ans.an[0].rname,  # Corrected field names for SOA
                }
                self.pretty_printer.pprint(
                    results,
                    title="DNS Request Results",
                    style="bold blue",  # Correct title
                )
                return results
            elif record_type == "MX":
                results = [x.exchange for x in ans.an]
                self.pretty_printer.pprint(
                    results,
                    title="DNS Request Results",
                    style="bold magenta",  # Correct title and style
                )
                return results  # Return MX records if available
        return None  # Return None for timeout or error

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
        self.pretty_printer.print_table_2("System Information", data)
