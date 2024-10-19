# network_modules/nmap_scanner.py

import nmap
import logging
from typing import Dict, List
from network_modules.helpers.utils import format_scan_result

logging.basicConfig(level=logging.DEBUG)


class NmapPortScanner:
    def __init__(self, arguments="-T4 -F"):
        """Initializes the NmapPortScanner with optional nmap arguments."""
        self.nm = nmap.PortScanner()
        self.arguments = arguments

    def scan_network(
        self, target: str, ports: List[int] = None
    ) -> Dict[str, List[int]]:
        """Scans a network range or a single IP for open ports using nmap.

        Args:
            target: The target IP address or CIDR range.
            ports: A list of ports to scan. If None, nmap's default scan is used.

        Returns:
            A dictionary where keys are IP addresses and values are lists of open ports.
        """
        logging.debug(
            f"Starting Nmap scan on {target} with arguments: {self.arguments}"
        )
        if ports:
            port_string = ",".join(str(port) for port in ports)
            self.nm.scan(hosts=target, arguments=self.arguments, ports=port_string)
        else:
            self.nm.scan(hosts=target, arguments=self.arguments)

        results = {}
        for ip in self.nm.all_hosts():
            results[ip] = [
                int(port)
                for port, state in self.nm[ip]["tcp"].items()
                if state["state"] == "open"
            ]
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
