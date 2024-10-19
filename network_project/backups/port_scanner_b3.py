#!/usr/bin/python3


import socket
import ipaddress
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed  # Import added


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


def _validate_target(target: str) -> None:
    """Validates that the target is a valid IP address or CIDR range.

    Args:
        target: The target IP address or CIDR range.

    Raises:
        ValueError: If the target is not a valid IP address or CIDR range.
    """
    try:
        ipaddress.ip_network(target)
    except ValueError as e:
        raise ValueError(f"Invalid IP address or CIDR range: {target}") from e


class PortScanner:
    def __init__(self, timeout: float = 1.0, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads

    def scan_port(self, ip: str, port: int) -> bool:
        """Scans a single port on a given IP address."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                return result == 0
        except socket.error:
            return False

    def scan_network(self, target: str, ports: List[int]) -> Dict[str, List[int]]:
        """Scans a network range or a single IP for open ports."""
        _validate_target(target)  # Validate target here
        results = {}
        try:
            # Validate the target before proceeding
            ipaddress.ip_network(target)  # This will raise ValueError for invalid input
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {
                    executor.submit(self._scan_host, str(ip), ports): ip
                    for ip in ipaddress.ip_network(target).hosts()
                }
                for future in as_completed(futures):
                    ip = futures[future]
                    results[ip] = future.result()
        except ValueError as e:  # Not a valid network, treat as a single IP
            raise ValueError(f"Invalid IP address or CIDR range: {target}") from e

        results[str(ip)] = future.result()

        return results

    def _scan_host(self, ip: str, ports: List[int]) -> List[int]:
        """Scans a single host for open ports."""
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self.scan_port, ip, port): port for port in ports
            }
            for future in as_completed(futures):
                port = futures[future]
                if future.result():
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
