#!/usr/bin/python3

import socket
import logging

import ipaddress
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from network_modules.helpers.utils import Utils  # Import the Utils class

logging.basicConfig(level=logging.DEBUG)


class PortScanner:
    def __init__(self, timeout: float = 2.08333, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.executor = ThreadPoolExecutor(
            max_workers=self.max_threads
        )  # Persistent thread pool

    def scan_port(self, ip: str, port: int) -> bool:
        # logging.debug(f"Attempting to scan {ip}:{port}")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)  # Use self.timeout here
                # logging.debug(f"Connecting to {ip}:{port}...")
                result = sock.connect_ex((ip, port))
                # logging.debug(f"Result for {ip}:{port}: {result}")
                return result == 0
        except socket.error as e:
            logging.debug(f"Error scanning {ip}:{port}: {e}")
            return False

    def scan_network(self, target: str, ports: List[int]) -> Dict[str, List[int]]:
        """Scans a network range or a single IP for open ports."""
        Utils.validate_target(target)  # Validate target here
        results = {}
        try:
            # Validate the target before proceeding
            ipaddress.ip_network(target)  # This will raise ValueError for invalid input
            futures = {
                self.executor.submit(self._scan_host, str(ip), ports): ip
                for ip in ipaddress.ip_network(target).hosts()
            }
            for future in as_completed(futures):
                ip = futures[future]
                results[str(ip)] = future.result()
        except ValueError as e:  # Not a valid network, treat as a single IP
            raise ValueError(f"Invalid IP address or CIDR range: {target}") from e

        return results

    def _scan_host(self, ip: str, ports: List[int]) -> List[int]:
        """Scans a single host for open ports."""
        open_ports = []
        futures = {
            self.executor.submit(self.scan_port, ip, port): port for port in ports
        }
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_ports.append(port)
        return open_ports

    def raw_print_results(self, results: Dict[str, List[int]]) -> None:
        """Prints the scan results to the console."""
        for ip, open_ports in results.items():
            print(Utils.format_scan_result(ip, open_ports))  # Consistent output
            if open_ports:
                for port in open_ports:
                    print(f"\tPort {port}: Open")  # Removed color codes
            else:
                print("\tNo open ports found")  # Removed color codes

    def print_results(self, results: Dict[str, List[int]]) -> None:
        """Prints the scan results to the console."""
        Utils.print_scan_results(results)  # Use the static method from Utils


if __name__ == "__main__":
    """Example usage of the port scanning functions."""
    scanner = PortScanner()
    target_ip = "192.168.1.1"  # Replace with your target IP or CIDR range
    ports_to_scan = [22, 80, 443, 3389]  # Replace with the ports you want to scan
    scan_results = scanner.scan_network(target_ip, ports_to_scan)
    Utils.print_scan_results(scan_results)
