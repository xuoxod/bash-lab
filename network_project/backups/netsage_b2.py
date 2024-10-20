#!/usr/bin/python3

import sys
import argparse
import logging
import nmap
import json
import csv

from network_modules.helpers.colors import TextColors
from network_modules import (
    port_scanner,
    nmap_port_scanner,
    scapy_port_scanner,  # Import the scapy_port_scanner module
)  # Import other modules as needed
from network_modules.helpers.parse_ports import parse_ports
from network_modules.helpers.regexes import Regexes
from network_modules.laneye import NetworkScanner


logging.basicConfig(level=logging.DEBUG)

# Default configuration (can be overridden by config file or command-line args)
DEFAULT_CONFIG = {
    "default_ports": [
        "22",
        "25",
        "53",
        "80",
        "110",
        "143",
        "443",
        "465",
        "993",
        "995",
        "3389",
        "587",
    ],
    "timeout": 2.0,  # Default timeout in seconds
    "nmap_arguments": "-T4 -F",
    "output_format": "text",  # Default output format
    "verbosity": "info",  # Default verbosity level
}


def load_config(config_file="./tests/unit/netsage.conf"):
    """Loads configuration from a JSON file."""
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        # If in testing mode, return an empty config
        if "unittest" in sys.modules:  # Check if running tests
            return {}
        logging.warning(
            f"Configuration file '{config_file}' not found. Using default settings."
        )
        return {}
    except json.JSONDecodeError:
        logging.error(
            f"Error decoding configuration file '{config_file}'. Using default settings."
        )
        return {}


def save_config(config, config_file="netsage.conf"):
    """Saves configuration to a JSON file."""
    try:
        with open(config_file, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        logging.error(f"Error saving configuration to '{config_file}': {e}")


def nmap_scan_command(args, config):
    """Handles the 'nmapscan' command."""
    if not Regexes.ip_cidr_regex.match(args.target):
        print(
            f"{TextColors.FAIL}Error during scan: Invalid IP address or CIDR range: {args.target}{TextColors.ENDC}"
        )
        exit(1)

    ports_to_scan = parse_ports(args.ports)

    try:
        scanner = nmap_port_scanner.NmapPortScanner(
            arguments=config.get("nmap_arguments", DEFAULT_CONFIG["nmap_arguments"])
        )
        results = scanner.scan_network(args.target, ports_to_scan)

        # Service/Version Detection (Basic for now)
        for ip, open_ports in results.items():
            print(f"{TextColors.OKGREEN}[+] {ip}:{TextColors.ENDC}")
            for port in open_ports:
                try:
                    nm = nmap.PortScanner()
                    nm.scan(ip, str(port), arguments="-sV")  # Version scan
                    service_info = nm[ip]["tcp"][port]["name"]
                    version_info = nm[ip]["tcp"][port]["version"]
                    print(f"\tPort {port}: Open - {service_info} ({version_info})")
                except Exception as e:
                    print(f"\tPort {port}: Open - Service/Version info: N/A")
        # Output based on format
        output_results(results, config)

    except nmap.nmap.PortScannerError as e:
        print(f"{TextColors.FAIL}Nmap Error: {e}{TextColors.ENDC}")
        exit(1)
    except ValueError as e:
        print(f"{TextColors.FAIL}Error during scan: {e}{TextColors.ENDC}")
        exit(1)


def scan_command(args, config):
    """Handles the 'scan' command for port scanning."""
    if not Regexes.ip_cidr_regex.match(args.target):
        print(
            f"{TextColors.FAIL}Error during scan: Invalid IP address or CIDR range: {args.target}{TextColors.ENDC}"
        )
        exit(1)
    ports_to_scan = parse_ports(args.ports)

    try:
        scanner = port_scanner.PortScanner(
            timeout=float(config.get("timeout", DEFAULT_CONFIG["timeout"]))
        )
        results = scanner.scan_network(args.target, ports_to_scan)
        output_results(results, config)
    except ValueError as e:
        print(f"{TextColors.FAIL}Error during scan: {e}{TextColors.ENDC}")
        exit(1)


def scapy_scan_command(args, config):  # New function for scapy scan
    """Handles the 'scapyscan' command for port scanning using Scapy."""
    if not Regexes.ip_cidr_regex.match(args.target):
        print(
            f"{TextColors.FAIL}Error during scan: Invalid IP address or CIDR range: {args.target}{TextColors.ENDC}"
        )
        exit(1)
    ports_to_scan = parse_ports(args.ports)

    try:
        scanner = scapy_port_scanner.ScapyPortScanner(
            timeout=float(config.get("timeout", DEFAULT_CONFIG["timeout"]))
        )
        results = scanner.scan_network(args.target, ports_to_scan)
        output_results(results, config)
    except ValueError as e:
        print(f"{TextColors.FAIL}Error during scan: {e}{TextColors.ENDC}")
        exit(1)


def output_results(results, config):
    """Outputs the scan results based on the configured format."""
    output_format = config.get("output_format", DEFAULT_CONFIG["output_format"])

    if output_format == "text":
        for ip, open_ports in results.items():
            print(f"{TextColors.OKGREEN}[+] {ip}:{TextColors.ENDC}")
            if open_ports:
                for port in open_ports:
                    print(f"\tPort {port}: Open")
            else:
                print("\tNo open ports found")
    elif output_format == "csv":
        print("IP,Open Ports")
        writer = csv.writer(sys.stdout)
        for ip, open_ports in results.items():
            writer.writerow([ip, ",".join(str(port) for port in open_ports)])
    elif output_format == "json":
        print(json.dumps(results, indent=4))
    else:
        print(
            f"{TextColors.FAIL}Invalid output format: {output_format}{TextColors.ENDC}"
        )
        exit(1)


def laneye_scan_command(args, config):
    """Handles the 'laneye' command."""
    if not Regexes.ip_cidr_regex.match(args.target):
        print(
            f"{TextColors.FAIL}Error during scan: Invalid IP address or CIDR range: {args.target}{TextColors.ENDC}"
        )
        exit(1)

    try:
        scanner = NetworkScanner()  # Create an instance of the NetworkScanner
        results = scanner.scan_network(args.target)
        scanner.print_results(results)  # Print results to console
    except ValueError as e:
        print(f"{TextColors.FAIL}Error during scan: {e}{TextColors.ENDC}")
        exit(1)


def main(args=None):
    """The main entry point for the NetSage CLI."""
    config = {**DEFAULT_CONFIG, **load_config()}  # Load config, override defaults

    parser = argparse.ArgumentParser(description="NetSage: Your Network Oracle")
    subparsers = parser.add_subparsers(
        dest="command",
        help="Available commands. Use 'netsage.py <command> -h' for more info.",
    )

    # Scan Command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a network for open ports using a pure Python implementation.",
    )
    scan_parser.add_argument(
        "target",
        help="The target IP address or CIDR range to scan. Example: 192.168.1.1 or 192.168.1.0/24",
    )
    scan_parser.add_argument(
        "-p",
        "--ports",
        type=str,
        nargs="+",
        help="Ports to scan (space or comma separated). Example: '80 443' or '80,443,8080'. Default: common ports (22, 25, 53, 80, 110, 143, 443, 465, 993, 995, 3389, 587)",
        default=config.get("default_ports", DEFAULT_CONFIG["default_ports"]),
    )

    # Nmap Scan Command
    nmap_scan_parser = subparsers.add_parser(
        "nmapscan",
        help="Scan a network for open ports using the Nmap port scanner.",
    )
    nmap_scan_parser.add_argument(
        "target",
        help="The target IP address or CIDR range to scan. Example: 192.168.1.1 or 192.168.1.0/24",
    )
    nmap_scan_parser.add_argument(
        "-p",
        "--ports",
        type=str,
        nargs="+",
        help="Ports to scan (space or comma separated). Example: '80 443' or '80,443,8080'. Default: Nmap's default port selection.",
        default=[],
    )

    # Scapy Scan Command
    scapy_scan_parser = subparsers.add_parser(  # Add the scapy scan parser
        "scapyscan",
        help="Scan a network for open ports using the Scapy library.",
    )
    scapy_scan_parser.add_argument(
        "target",
        help="The target IP address or CIDR range to scan. Example: 192.168.1.1 or 192.168.1.0/24",
    )
    scapy_scan_parser.add_argument(
        "-p",
        "--ports",
        type=str,
        nargs="+",
        help="Ports to scan (space or comma separated). Example: '80 443' or '80,443,8080'. Default: common ports (22, 25, 53, 80, 110, 143, 443, 465, 993, 995, 3389, 587)",
        default=config.get("default_ports", DEFAULT_CONFIG["default_ports"]),
    )

    # Laneye Scan Command
    laneye_scan_parser = subparsers.add_parser(
        "laneye", help="Scan a network using ARP requests."
    )
    laneye_scan_parser.add_argument(
        "target",
        help="The target IP address or CIDR range to scan. Example: 192.168.1.1 or 192.168.1.0/24",
    )

    args = parser.parse_args()

    if args.command == "nmapscan":
        nmap_scan_command(args, config)
    elif args.command == "scan":
        scan_command(args, config)
    elif args.command == "scapyscan":  # Handle the 'scapyscan' command
        scapy_scan_command(args, config)
    elif args.command == "laneye":
        laneye_scan_command(args, config)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
