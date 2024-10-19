# network_modules/scapy_port_scanner.py

import logging
from typing import Dict, List

from scapy.all import sr1, IP, TCP, ICMP
from scapy.layers.inet import TCP, ICMP
from network_modules.helpers.utils import format_scan_result

logging.basicConfig(level=logging.DEBUG)


class ScapyPortScanner:
    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout

    def scan_port(self, ip: str, port: int) -> bool:
        """Scans a single port on a target IP using Scapy."""
        packet = IP(dst=ip) / TCP(dport=port, flags="S")  # SYN packet
        response = sr1(packet, timeout=self.timeout, verbose=0)

        if response is None:
            return False  # No response
        elif response.haslayer(TCP):
            if response[TCP].flags == "SA":  # SYN-ACK received
                return True
            else:
                return False
        elif response.haslayer(ICMP):
            # ICMP response (likely port closed/filtered)
            return False

    def scan_network(self, target: str, ports: List[int]) -> Dict[str, List[int]]:
        """Scans a network range or a single IP for open ports using Scapy.

        Args:
            target: The target IP address or CIDR range.
            ports: A list of ports to scan.

        Returns:
            A dictionary where keys are IP addresses and values are lists of open ports.
        """
        results = {}
        for ip in target:
            results[ip] = []
            for port in ports:
                if self.scan_port(ip, port):
                    results[ip].append(port)
        return results

    def print_results(self, results: Dict[str, List[int]]) -> None:
        """Prints the scan results to the console."""
        for ip, open_ports in results.items():
            print(format_scan_result(ip, open_ports))
            if open_ports:
                for port in open_ports:
                    print(f"\tPort {port}: Open")
            else:
                print("\tNo open ports found")
