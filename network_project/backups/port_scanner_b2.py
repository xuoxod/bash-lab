#!/usr/bin/python3

import socket
import ipaddress
from typing import Dict, List


# ANSI escape codes for text coloring
class TextColors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


class PortScanner:
    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    def scan_port(self, ip: str, port: int) -> bool:
        """Scans a single port on a given IP address.

        Args:
            ip (str): The IP address to scan.
            port (int): The port number to scan.

        Returns:
            bool: True if the port is open, False otherwise.
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                return result == 0
        except socket.error:
            return False

    def scan_network(self, target: str, ports: List[int]) -> Dict[str, List[int]]:
        """Scans a network range or a single IP for open ports.

        Args:
            target (str): The target IP address or CIDR range.
            ports (list): A list of ports to scan.

        Returns:
            dict: A dictionary of results, where keys are IP addresses
                  and values are lists of open ports.
        """
        results = {}
        try:
            for ip in ipaddress.ip_network(target).hosts():
                ip = str(ip)
                results[ip] = self._scan_host(ip, ports)
        except ValueError:  # Not a valid network, treat as a single IP
            results[target] = self._scan_host(target, ports)
        return results

    def _scan_host(self, ip: str, ports: List[int]) -> List[int]:
        """Scans a single host for open ports.

        Args:
            ip (str): The IP address of the host.
            ports (List[int]): The list of ports to scan.

        Returns:
            List[int]: A list of open ports.
        """
        open_ports = []
        for port in ports:
            if self.scan_port(ip, port):
                open_ports.append(port)
        return open_ports

    def print_results(self, results: Dict[str, List[int]]) -> None:
        """Prints the scan results to the console.

        Args:
            results (dict): The scan results dictionary.
        """
        for ip, open_ports in results.items():
            if open_ports:
                print(f"{TextColors.OKGREEN}[+] {ip}:{TextColors.ENDC}")
                for port in open_ports:
                    print(f"{TextColors.OKBLUE}\tPort {port}: Open{TextColors.ENDC}")
            else:
                print(
                    f"{TextColors.FAIL}[-] {ip}: No open ports found{TextColors.ENDC}"
                )


if __name__ == "__main__":
    """Example usage of the port scanning functions."""
    scanner = PortScanner()
    target_ip = "192.168.1.1"  # Replace with your target IP or CIDR range
    ports_to_scan = [22, 80, 443, 3389]  # Replace with the ports you want to scan
    scan_results = scanner.scan_network(target_ip, ports_to_scan)
    scanner.print_results(scan_results)
