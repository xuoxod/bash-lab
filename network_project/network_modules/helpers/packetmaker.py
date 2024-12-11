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

    def _print_results(self, results, title, style="white"):  # Helper function
        """Prints the results using the pretty printer."""
        self.pretty_printer.pprint(results, title=title, style=style)

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

    def ack_scan(self, dst_ip, ports, verbose=0):
        """Performs an ACK scan on the specified ports."""
        ans, unans = sr(
            IP(dst=dst_ip) / TCP(dport=ports, flags="A"), timeout=2, verbose=verbose
        )

        unfiltered_ports = []
        filtered_ports = []

        for sent, received in ans:
            if sent[TCP].dport == received[TCP].sport:  # Check for unfiltered ports
                unfiltered_ports.append(sent[TCP].dport)

        for sent in unans:  # Unanswered packets indicate filtered ports
            filtered_ports.append(sent[TCP].dport)

        results = {
            "Unfiltered Ports": unfiltered_ports,
            "Filtered Ports": filtered_ports,
        }
        self.pretty_printer.pprint(
            results, title="ACK Scan Results", style="bold yellow"
        )

        return unfiltered_ports, filtered_ports  # Return both lists of ports

    def xmas_scan(self, dst_ip, ports, verbose=0):
        """Performs a Xmas scan on the specified ports."""
        ans, unans = sr(
            IP(dst=dst_ip) / TCP(dport=ports, flags="FPU"), timeout=2, verbose=verbose
        )

        closed_ports = []  # Collect closed or filtered ports
        for sent, received in ans:
            if (
                received.haslayer(TCP) and received[TCP].flags == "RA"
            ):  # Check for RST-ACK
                closed_ports.append(sent.dport)
        for sent in unans:  # Append filtered ports from unanswered packets
            closed_ports.append(sent.dport)

        results = {"Closed/Filtered Ports": closed_ports}
        self.pretty_printer.pprint(results, title="Xmas Scan Results", style="bold red")
        return closed_ports

    def ip_scan(self, dst_ip, verbose=0):
        """Performs a protocol scan (IP scan) on the specified destination."""
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
        """Performs an ARP ping to discover hosts on the local network."""
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

    def icmp_ping(self, target_network, verbose=0):
        """Performs an ICMP ping to discover live hosts."""
        ans, unans = sr(IP(dst=target_network) / ICMP(), timeout=2, verbose=verbose)
        live_hosts = []
        for sent, received in ans:
            live_hosts.append(received.src)

        results = {"Live Hosts": live_hosts}
        self.pretty_printer.pprint(
            results, title="ICMP Ping Results", style="bold green"
        )
        return live_hosts

    def tcp_ping(self, target_network, dport=80, verbose=0):
        """Performs a TCP SYN ping to discover live hosts."""
        ans, unans = sr(
            IP(dst=target_network) / TCP(dport=dport, flags="S"),
            timeout=2,
            verbose=verbose,
        )
        live_hosts = []
        for sent, received in ans:
            live_hosts.append(received.src)

        results = {"Live Hosts": live_hosts}
        self.pretty_printer.pprint(results, title="TCP Ping Results", style="bold cyan")
        return live_hosts

    def udp_ping(self, target_network, dport=0, verbose=0):
        """Performs a UDP ping to discover live hosts."""
        ans, unans = sr(
            IP(dst=target_network) / UDP(dport=dport), timeout=2, verbose=verbose
        )
        live_hosts = []
        for sent, received in ans:  # Check both ICMP unreachable and UDP replies
            if (
                received.haslayer(ICMP) and received[ICMP].type == 3
            ):  # ICMP Port Unreachable
                live_hosts.append(received.src)
            elif received.haslayer(UDP):  # Consider direct UDP replies as live
                live_hosts.append(received.src)

        results = {"Live Hosts": live_hosts}
        self.pretty_printer.pprint(
            results, title="UDP Ping Results", style="bold yellow"
        )

        return live_hosts

    def dns_request(self, target_dns, domain, record_type="A", verbose=0):
        """Makes a DNS request for a specific record type."""
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
                )
                return ans.an[0].rdata
            elif record_type == "SOA":
                results = {
                    "mname": ans.an[0].mname,
                    "rname": ans.an[0].rname,
                }
                self.pretty_printer.pprint(
                    results, title="DNS Request Results", style="bold blue"
                )
                return results
            elif record_type == "MX":
                results = [x.exchange for x in ans.an]
                self.pretty_printer.pprint(
                    results, title="DNS Request Results", style="bold magenta"
                )
                return results
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
        self.pretty_printer.print_table_2(
            "System Information", data
        )  # Use print_table_2
