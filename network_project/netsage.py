#!/usr/bin/python3

import sys
import argparse
import logging
import ipaddress
import json
import csv
import time

from network_modules.helpers.colors import TextColors
from network_modules import (
    port_scanner,
    nmap_port_scanner,
    scapy_port_scanner,
    packetmaster,
    laneye,
)
from network_modules.helpers.parse_ports import parse_ports
from network_modules.traffic_interceptor import TrafficInterceptor


# Set up logging
logging.basicConfig(level=logging.INFO)  # Set default logging level to INFO

# Default configuration
DEFAULT_CONFIG = {
    "default_ports": "22,25,53,80,110,143,443,465,993,995,3389,587",
    "timeout": 2.0,
    "nmap_arguments": "-T4 -F",
    "output_format": "text",
    "verbosity": "info",
}


def load_config(config_file="./tests/unit/netsage.conf"):
    """Loads configuration from a JSON file."""
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        if "unittest" in sys.modules:
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


def packetmaster_command(args, config):
    """Handles the 'packetmaster' command."""
    targets = args.target.split(",")
    port = args.port
    data = args.data
    protocol = args.protocol
    output_file = args.output_file

    results = packetmaster.scan_targets(targets, port, data, protocol, output_file)

    if not output_file:
        for result in results:
            print(json.dumps(result, indent=4))


def laneye_scan_command(args, config):
    """Handles the 'laneye' command."""
    scanner = laneye.NetworkScanner()
    try:
        results = scanner.scan_network(args.target)
    except ValueError as e:
        print(f"{TextColors.FAIL}Error: {e}{TextColors.ENDC}")
        sys.exit(1)

    if args.output:
        if args.output == "csv":
            scanner.save_to_csv(results, "network_scan.csv")
            print(
                f"{TextColors.OKGREEN}[+] Results saved to network_scan.csv{TextColors.ENDC}"
            )
        elif args.output == "json":
            scanner.save_to_json(results, "network_scan.json")
            print(
                f"{TextColors.OKGREEN}[+] Results saved to network_scan.json{TextColors.ENDC}"
            )
        elif args.output == "html":
            scanner.save_to_html(results, "network_scan.html")
            print(
                f"{TextColors.OKGREEN}[+] Results saved to network_scan.html{TextColors.ENDC}"
            )
    else:
        scanner.print_results(results)


def main():
    """Main entry point for NetSage CLI."""
    config = load_config()
    config = {**DEFAULT_CONFIG, **config}  # Merge default and loaded config

    parser = argparse.ArgumentParser(
        description="NetSage: A versatile network scanning and analysis tool"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # TrafficInterceptor Command
    traffic_interceptor_parser = subparsers.add_parser(
        "traffic-interceptor", help="Reroute traffic from a target on the LAN"
    )
    traffic_interceptor_parser.add_argument("target", help="Target IP address")

    # Nmap Scan Command
    nmap_parser = subparsers.add_parser(
        "nmapscan", help="Perform an nmap scan with custom arguments"
    )
    nmap_parser.add_argument("target", help="Target IP address or CIDR range")
    nmap_parser.add_argument(
        "-p",
        "--ports",
        type=str,
        help="Comma-separated list of ports or port ranges (e.g., 22,80-85,443)",
    )
    nmap_parser.add_argument(
        "-o",
        "--output",
        choices=["csv", "json", "html", "text"],
        help="Save output to file (csv, json, html, text)",
    )

    # Scan Command
    scan_parser = subparsers.add_parser(
        "scan", help="Perform a basic port scan using Python sockets"
    )
    scan_parser.add_argument("target", help="Target IP address or CIDR range")
    scan_parser.add_argument(
        "-p",
        "--ports",
        type=str,
        help="Comma-separated list of ports or port ranges (e.g., 22,80-85,443)",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        choices=["csv", "json", "html", "text"],
        help="Save output to file (csv, json, html, text)",
    )

    # Scapy Scan Command
    scapy_parser = subparsers.add_parser(
        "scapyscan", help="Perform a port scan using Scapy"
    )
    scapy_parser.add_argument("target", help="Target IP address or CIDR range")
    scapy_parser.add_argument(
        "-p",
        "--ports",
        type=str,
        help="Comma-separated list of ports or port ranges (e.g., 22,80-85,443)",
    )
    scapy_parser.add_argument(
        "-o",
        "--output",
        choices=["csv", "json", "html", "text"],
        help="Save output to file (csv, json, html, text)",
    )

    # Laneye Scan Command
    laneye_parser = subparsers.add_parser(
        "laneye", help="Perform a network scan using ARP requests"
    )
    laneye_parser.add_argument("target", help="Target IP address or CIDR range")
    laneye_parser.add_argument(
        "-o",
        "--output",
        choices=["csv", "json", "html"],
        help="Save output to file (csv, json, html)",
    )

    # PacketMaster Command
    packetmaster_parser = subparsers.add_parser(
        "packetmaster", help="Send and receive custom network packets"
    )
    packetmaster_parser.add_argument(
        "target", help="Target IP address (or multiple targets separated by commas)"
    )
    packetmaster_parser.add_argument(
        "-p", "--port", type=int, help="Destination port (optional)"
    )
    packetmaster_parser.add_argument(
        "-d", "--data", help="Payload data to include in the packet (optional)"
    )
    packetmaster_parser.add_argument(
        "-prot",
        "--protocol",
        choices=["tcp", "udp", "icmp"],
        default="icmp",
        help="Protocol to use (tcp, udp, icmp). Default: icmp",
    )
    packetmaster_parser.add_argument(
        "-o",
        "--output-file",
        help="Optional output filename for saving results to a CSV file",
    )

    args = parser.parse_args()

    if args.command == "nmapscan":
        nmap_scan_command(args, config)
    elif args.command == "scan":
        scan_command(args, config)
    elif args.command == "scapyscan":
        scapy_scan_command(args, config)
    elif args.command == "laneye":
        laneye_scan_command(args, config)
    elif args.command == "packetmaster":
        packetmaster_command(args, config)
    elif args.command == "traffic-interceptor":
        try:
            interceptor = TrafficInterceptor(args.target)
            interceptor.start()
            # Keep the script running until manually stopped (e.g., Ctrl+C)
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nStopping traffic interception...")
            finally:
                interceptor.stop()  # Ensure restoration even if an error occurs
        except ValueError as e:
            print(f"{TextColors.FAIL}Error: {e}{TextColors.ENDC}")
            sys.exit(1)
    else:
        parser.print_help()


def nmap_scan_command(args, config):
    """Handles the 'nmapscan' command."""
    scanner = nmap_port_scanner.NmapPortScanner(arguments=config["nmap_arguments"])
    ports = parse_ports(args.ports) if args.ports else None
    results = scanner.scan_network(args.target, ports)

    if args.output:
        save_results(results, args.output, "nmap_scan_results")
    else:
        scanner.print_results(results)


def scan_command(args, config):
    """Handles the 'scan' command."""
    scanner = port_scanner.PortScanner(
        timeout=config["timeout"], max_threads=config.get("max_threads", 100)
    )
    ports = (
        parse_ports(args.ports) if args.ports else parse_ports(config["default_ports"])
    )
    try:
        results = scanner.scan_network(args.target, ports)
    except ValueError as e:
        print(f"{TextColors.FAIL}Error: {e}{TextColors.ENDC}")
        sys.exit(1)

    if args.output:
        save_results(results, args.output, "port_scan_results")
    else:
        scanner.print_results(results)


def scapy_scan_command(args, config):
    """Handles the 'scapyscan' command."""
    scanner = scapy_port_scanner.ScapyPortScanner(timeout=config["timeout"])
    ports = (
        parse_ports(args.ports) if args.ports else parse_ports(config["default_ports"])
    )
    try:
        target_ips = [str(ip) for ip in ipaddress.ip_network(args.target).hosts()]
        results = scanner.scan_network(target_ips, ports)
    except ValueError as e:
        print(f"{TextColors.FAIL}Error: {e}{TextColors.ENDC}")
        sys.exit(1)

    if args.output:
        save_results(results, args.output, "scapy_scan_results")
    else:
        scanner.print_results(results)


def save_results(results, output_format, filename_prefix):
    """Saves the scan results to a file in the specified format."""
    if output_format == "json":
        filename = f"{filename_prefix}.json"
        with open(filename, "w") as f:
            json.dump(results, f, indent=4)
        print(f"{TextColors.OKGREEN}[+] Results saved to {filename}{TextColors.ENDC}")
    elif output_format == "csv":
        filename = f"{filename_prefix}.csv"
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP Address", "Open Ports"])
            for ip, ports in results.items():
                writer.writerow([ip, ",".join(str(p) for p in ports)])
        print(f"{TextColors.OKGREEN}[+] Results saved to {filename}{TextColors.ENDC}")
    elif output_format == "html":
        filename = f"{filename_prefix}.html"
        with open(filename, "w") as f:
            f.write("<html><body><table>\n")
            f.write("<tr><th>IP Address</th><th>Open Ports</th></tr>\n")
            for ip, ports in results.items():
                f.write(
                    f"<tr><td>{ip}</td><td>{','.join(str(p) for p in ports)}</td></tr>\n"
                )
            f.write("</table></body></html>\n")
        print(f"{TextColors.OKGREEN}[+] Results saved to {filename}{TextColors.ENDC}")
    elif output_format == "text":
        for ip, ports in results.items():
            print(f"{TextColors.OKGREEN}IP Address: {ip}{TextColors.ENDC}")
            if ports:
                print(
                    f"{TextColors.OKBLUE}Open Ports: {', '.join(str(p) for p in ports)}{TextColors.ENDC}"
                )
            else:
                print(f"{TextColors.FAIL}No open ports found{TextColors.ENDC}")


if __name__ == "__main__":
    main()
