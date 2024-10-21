#!/usr/bin/python3

import logging
from typing import Dict, List
import ipaddress

logging.basicConfig(level=logging.DEBUG)


class Utils:
    """A class containing utility functions for network scanning."""

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

    @staticmethod
    def is_valid_ip(ip_address: str) -> bool:
        """Checks if an IP address or CIDR range is valid."""
        try:
            ipaddress.ip_network(ip_address)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_target(target: str) -> None:
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

    @staticmethod
    def format_scan_result(ip: str, open_ports: List[int]) -> str:
        """Formats the scan results for consistent output."""
        if open_ports:
            port_string = ", ".join([f"Port {port}: Open" for port in open_ports])
            return f"{Utils.TextColors.OKGREEN}[+] {ip}:{Utils.TextColors.ENDC}\n{port_string}"
        else:
            return f"{Utils.TextColors.OKGREEN}[+] {ip}:{Utils.TextColors.ENDC}\n{Utils.TextColors.FAIL}No open ports found{Utils.TextColors.ENDC}"

    @staticmethod
    def print_scan_results(results: Dict[str, List[int]]) -> None:
        """Prints the scan results to the console."""
        for ip, open_ports in results.items():
            print(Utils.format_scan_result(ip, open_ports))
