#!/usr/bin/python3


import socket
from scapy.all import *
from scapy.all import IP, Ether, ARP, UDP, TCP, ICMP
from .prettyprinter import PrettyPrinter as pp
from networkexceptions import NoIPError


class NetworkScanner:
    def __init__(self, own_ip, own_mac, interface=None):
        self.interface = interface
        self.own_ip = own_ip
        self.own_mac = own_mac
        self.pretty_printer = pp()

    def ack_scan(self, dst_ip, ports, verbose=0):
        ans, unans = sr(
            IP(dst=dst_ip) / TCP(dport=ports, flags="A"),
            timeout=2,
            verbose=verbose,
            iface=self.interface,  # Use the provided interface
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
        self._print_results(
            results, "ACK Scan Results", style="bold yellow"
        )  # Use _print_results

        return unfiltered_ports, filtered_ports  # Return both lists

    def xmas_scan(self, dst_ip, ports, verbose=0):
        ans, unans = sr(
            IP(dst=dst_ip) / TCP(dport=ports, flags="FPU"),
            timeout=2,
            verbose=verbose,
            iface=self.interface,
        )

        closed_filtered_ports = []  # More accurate name
        for sent, received in ans:
            if (
                received.haslayer(TCP) and received[TCP].flags == "RA"
            ):  # Check for RST/ACK flags
                closed_filtered_ports.append(sent[TCP].dport)

        for sent in unans:
            closed_filtered_ports.append(sent[TCP].dport)

        results = {"Closed/Filtered Ports": closed_filtered_ports}
        self._print_results(
            results, "Xmas Scan Results", style="bold red"
        )  # Use _print_results
        return closed_filtered_ports

    def ip_scan(self, dst_ip, verbose=0):  # Now in NetworkScanner
        ans, unans = sr(
            IP(dst=dst_ip, proto=(0, 255)) / "SCAPY",
            retry=2,
            timeout=2,
            verbose=verbose,
            iface=self.interface,
        )
        supported_protocols = []
        for sent, received in ans:
            supported_protocols.append(sent.proto)

        results = {"Supported Protocols": supported_protocols}
        self._print_results(
            results, title="IP Scan Results", style="bold blue"
        )  # Use self.print_results
        return supported_protocols

    def arp_ping(self, target_network, verbose=0):
        ans, unans = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_network),
            timeout=2,
            verbose=verbose,
            iface=self.interface,
        )
        live_hosts = []
        for sent, received in ans:
            live_hosts.append((received.psrc, received.hwsrc))

        results = {"Live Hosts": live_hosts}
        self._print_results(results, "ARP Ping Results", style="bold magenta")
        return live_hosts

    def icmp_ping(self, target_network, verbose=0):
        ans, unans = sr(
            IP(dst=target_network) / ICMP(),
            timeout=2,
            verbose=verbose,
            iface=self.interface,
        )
        live_hosts = []
        for sent, received in ans:
            live_hosts.append(received.src)

        results = {"Live Hosts": live_hosts}
        self._print_results(results, "ICMP Ping Results", style="bold green")
        return live_hosts

    def tcp_ping(self, target_network, dport=80, verbose=0):
        ans, unans = sr(
            IP(dst=target_network) / TCP(dport=dport, flags="S"),
            timeout=2,
            verbose=verbose,
            iface=self.interface,
        )
        live_hosts = []
        for sent, received in ans:
            live_hosts.append(received.src)

        results = {"Live Hosts": live_hosts}
        self._print_results(results, "TCP Ping Results", style="bold cyan")
        return live_hosts

    def udp_ping(self, target_network, dport=0, verbose=0):  # Now in NetworkScanner
        ans, unans = sr(
            IP(dst=target_network) / UDP(dport=dport),
            timeout=2,
            verbose=verbose,
            iface=self.interface,
        )

        live_hosts = []
        for sent, received in ans:
            if (
                received.haslayer(ICMP) and received[ICMP].type == 3
            ):  # Check for ICMP unreachable

                live_hosts.append(received.src)  # Add the source IP to live hosts

            elif received.haslayer(UDP):  # Also check for direct replies
                live_hosts.append(received.src)  # Append the host to live_hosts

        results = {"Live Hosts": live_hosts}
        self._print_results(
            results, title="UDP Ping Results", style="bold yellow"
        )  # Use _print_results

        return live_hosts  # Return results

    def _print_results(self, results, title, style="white"):
        self.pretty_printer.pprint(results, title=title, style=style)
