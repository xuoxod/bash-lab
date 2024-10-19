#!/usr/bin/python3

import socket
import ipaddress


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


def scan_port(ip, port):
    """Scans a single port on a given IP address.

    Args:
        ip (str): The IP address to scan.
        port (int): The port number to scan.

    Returns:
        bool: True if the port is open, False otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # Set a timeout of 1 second
            result = sock.connect_ex((ip, port))
            if result == 0:
                return True
            else:
                return False
    except socket.error:
        return False


def scan_network(target, ports):
    """Scans a network range for open ports.

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
            results[ip] = []
            for port in ports:
                if scan_port(ip, port):
                    results[ip].append(port)
    except ValueError:
        results[target] = []
        for port in ports:
            if scan_port(target, port):
                results[target].append(port)
    return results


def print_results(results):
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
            print(f"{TextColors.FAIL}[-] {ip}: No open ports found{TextColors.ENDC}")


if __name__ == "__main__":
    """Example usage of the port scanning functions."""

    target_ip = "192.168.1.1"  # Replace with your target IP or CIDR range
    ports_to_scan = [22, 80, 443, 3389]  # Replace with the ports you want to scan

    scan_results = scan_network(target_ip, ports_to_scan)
    print_results(scan_results)
