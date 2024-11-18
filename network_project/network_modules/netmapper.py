#!/usr/bin/python3


import scapy.all as scapy
import socket
import ipaddress
import platform
import subprocess
import argparse


class TextColors:  # (From neteye.py or your utils module)
    # ... (Color definitions)
    pass


class NetMapper:  # Robust, nerdy, one-word class name
    def __init__(self):
        self.results = {}

    def scan_network(self, net_address):
        # ... (Existing scan_network implementation from netdiscover.py, with robust error handling)
        pass

    def get_hostname(self, ip):
        # ... (Existing get_hostname from netdiscover.py)
        pass

    def get_os_hint(self, ip):
        # ... (Existing get_os_hint implementation, potentially enhanced)
        pass

    def print_results(self, results=None):  # Takes optional results for library use
        if results is None:
            results = self.results  # Use stored results if none are passed

        # ... (Existing print_results from netdiscover.py - use results parameter)
        pass

    def save_results(
        self, format="json", filename="network_scan"
    ):  # Unified save method
        if format == "json":
            # ... (JSON saving logic - include hostname and OS hint)
            pass
        elif format == "csv":
            # ... (CSV saving logic - include hostname and OS hint)
            pass
        elif format == "html":
            # ... (HTML saving logic - include hostname and OS hint)
            pass


def main():
    parser = argparse.ArgumentParser(
        description="""NetMapper: A robust tool for discovering and mapping devices on your network.
        Performs ARP scans to identify active hosts, resolves hostnames, and provides basic OS hints.
        Can output results to the console, JSON, CSV, or HTML.""",
        epilog="""Examples:
            netmapper.py 192.168.1.0/24          (Scan the 192.168.1.0/24 network)
            netmapper.py 192.168.1.1-100         (Scan a range of IPs)
            netmapper.py 192.168.1.1 10.0.0.1    (Scan specific IPs)
            netmapper.py -o json                (Scan current network, save to JSON)
            netmapper.py 192.168.5.0/24 -o csv --filename my_scan  (Save to 'my_scan.csv')
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,  # For better formatting
    )

    parser.add_argument(
        "targets",
        nargs="*",
        help="Target IP address(es) or network range(s) to scan (e.g., 192.168.1.0/24, 10.0.0.1).",
    )
    parser.add_argument(
        "-o",
        "--output",
        choices=["json", "csv", "html"],
        help="Output format (json, csv, html).",
    )
    parser.add_argument("--filename", help="Output filename (without extension).")

    args = parser.parse_args()

    mapper = NetMapper()

    if not args.targets:  # No target provided
        target_network = scapy.get_if_addr(scapy.conf.iface) + "/24"  # Default network
        mapper.scan_network(target_network)

    else:  # Scan the specified network
        for target in args.targets:  # Handle multiple targets from command line
            mapper.scan_network(target)

    mapper.print_results()  # Print to console (always)

    if args.output:
        filename = args.filename or "network_scan"  # Use provided or default name
        mapper.save_results(args.output, filename)
        print(
            f"{TextColors.OKGREEN}Results saved to {filename}.{args.output}{TextColors.ENDC}"
        )


if __name__ == "__main__":
    main()
