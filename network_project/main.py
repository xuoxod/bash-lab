#!/usr/bin/python3

import argparse
import logging
import time
from network_modules import (
    port_scanner,
    nmap_port_scanner,
    scapy_port_scanner,
    packetmaster,  # Import the packetmaster module
)
from network_modules.helpers.parse_ports import parse_ports
from network_modules.traffic_interceptor import TrafficInterceptor

logging.basicConfig(level=logging.INFO)


def main():
    """
    NetSage Scanner: A versatile network scanning and analysis tool.

    This script allows you to perform various network operations, including:

    - Port Scanning:
        - Nmap: Leverages the power of the Nmap scanner for comprehensive results.
        - Socket: Uses Python sockets for a more lightweight scan.
        - Scapy: Employs the Scapy library for crafting and sending custom packets.

    - Packet Manipulation:
        - PacketMaster: Send and receive custom network packets using various protocols
          (TCP, UDP, ICMP). This allows for more advanced network probing and testing.

    - Traffic Interception:
        - Traffic Interceptor: Reroute traffic from a target on the LAN to your machine
          using ARP spoofing. This enables you to analyze network traffic in real-time.

    Choose the method that best suits your needs and target network.
    """
    parser = argparse.ArgumentParser(
        description="NetSage Scanner: A versatile network scanning and analysis tool.",
        epilog="""
        Examples:

        # Port Scanning:
        - Scan a single IP using Nmap with default arguments:
            python main.py nmap 192.168.1.1

        - Scan a range of IPs using Python sockets with custom ports and timeout:
            python main.py socket 192.168.1.0/24 -p 22,80,443 -t 1.5

        - Scan specific ports on a host using Scapy with a longer timeout:
            python main.py scapy 192.168.1.100 -p 22,8080 -t 3.0

        # Packet Manipulation (PacketMaster):
        - Send an ICMP echo request to a target:
            python main.py packetmaster 192.168.1.1

        - Send a TCP SYN packet to a specific port:
            python main.py packetmaster 192.168.1.1 -p 80 -prot tcp

        - Send a UDP packet with custom data:
            python main.py packetmaster 192.168.1.1 -p 53 -prot udp -d "Hello, UDP!"

        # Traffic Interception:
        - Reroute traffic from a target IP:
            python main.py traffic-interceptor 192.168.1.100

        For more detailed help on a specific command, use:
        python main.py <command> -h
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,  # Preserve formatting
    )
    subparsers = parser.add_subparsers(
        dest="command", help="Choose the network operation to perform."
    )

    # --- Common Arguments for Port Scanners ---
    common_port_scan_args = argparse.ArgumentParser(add_help=False)
    common_port_scan_args.add_argument(
        "target",
        help="""
        The target IP address or CIDR range to scan. 

        Examples:
        - Single IP: 192.168.1.1
        - IP range: 192.168.1.1-192.168.1.254
        - CIDR notation: 192.168.1.0/24
        """,
    )
    common_port_scan_args.add_argument(
        "-p",
        "--ports",
        type=str,
        help="""
        Comma-separated list of ports or port ranges to scan. 
        If not provided, default ports will be used.

        Examples:
        - Single port: 80
        - Multiple ports: 22,80,443
        - Port range: 1-100
        - Mixed: 22,80-85,443
        """,
    )

    # --- Nmap Scanner ---
    nmap_parser = subparsers.add_parser(
        "nmap",
        help="Perform a port scan using Nmap.",
        parents=[common_port_scan_args],
    )
    nmap_parser.add_argument(
        "-a",
        "--arguments",
        type=str,
        default="-T4 -F",
        help="""
        Custom Nmap arguments to use during the scan. 
        Refer to Nmap documentation for available options.

        Examples:
        - Fast scan: -T4 -F
        - Aggressive scan: -T4 -A -v
        - Service version detection: -sV
        """,
    )

    # --- Socket Scanner ---
    socket_parser = subparsers.add_parser(
        "socket",
        help="Perform a port scan using Python sockets.",
        parents=[common_port_scan_args],
    )
    socket_parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        help="""
        Timeout in seconds for each connection attempt.

        Examples:
        - Default timeout: 2.0
        - Shorter timeout: 1.0
        - Longer timeout: 5.0
        """,
    )
    socket_parser.add_argument(
        "-th",
        "--threads",
        type=int,
        default=100,
        help="""
        Maximum number of threads to use for concurrent scanning.

        Examples:
        - Default threads: 100
        - Fewer threads: 50
        - More threads: 200
        """,
    )

    # --- Scapy Scanner ---
    scapy_parser = subparsers.add_parser(
        "scapy",
        help="Perform a port scan using Scapy.",
        parents=[common_port_scan_args],
    )
    scapy_parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=2.0,
        help="""
        Timeout in seconds for waiting for packet responses.

        Examples:
        - Default timeout: 2.0
        - Shorter timeout: 1.0
        - Longer timeout: 3.0
        """,
    )

    # --- PacketMaster ---
    packetmaster_parser = subparsers.add_parser(
        "packetmaster",
        help="Send and receive custom network packets.",
    )
    packetmaster_parser.add_argument(
        "target",
        help="""
        The target IP address to send packets to.

        Example:
        - 192.168.1.100
        """,
    )
    packetmaster_parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="""
        Destination port for TCP and UDP packets. 
        Optional for ICMP.

        Example:
        - 80 (for HTTP)
        """,
    )
    packetmaster_parser.add_argument(
        "-d",
        "--data",
        help="""
        Payload data to include in the packet (optional).

        Example:
        - "Hello, world!"
        """,
    )
    packetmaster_parser.add_argument(
        "-prot",
        "--protocol",
        choices=["tcp", "udp", "icmp"],
        default="icmp",
        help="""
        Protocol to use for sending packets. 
        Options: tcp, udp, icmp. 
        Default: icmp
        """,
    )
    packetmaster_parser.add_argument(
        "-o",
        "--output-file",
        help="""
        Optional output filename for saving results to a CSV file.

        Example:
        - packet_results.csv
        """,
    )

    # --- Traffic Interceptor ---
    traffic_interceptor_parser = subparsers.add_parser(
        "traffic-interceptor",
        help="Reroute traffic from a target on the LAN.",
    )
    traffic_interceptor_parser.add_argument(
        "target",
        help="""
        The target IP address to intercept traffic from.

        Example:
        - 192.168.1.100
        """,
    )

    args = parser.parse_args()

    # --- Parse Ports ---
    try:
        ports = parse_ports(args.ports) if args.ports else None
    except ValueError as e:
        print(f"Error parsing ports: {e}")
        return

    # --- Execute Commands ---
    if args.command == "nmap":
        scanner = nmap_port_scanner.NmapPortScanner(arguments=args.arguments)
        try:
            results = scanner.scan_network(args.target, ports)
            scanner.print_results(results)
        except Exception as e:
            print(f"Error during scan: {e}")
    elif args.command == "socket":
        scanner = port_scanner.PortScanner(
            timeout=args.timeout, max_threads=args.threads
        )
        try:
            results = scanner.scan_network(args.target, ports)
            scanner.print_results(results)
        except Exception as e:
            print(f"Error during scan: {e}")
    elif args.command == "scapy":
        scanner = scapy_port_scanner.ScapyPortScanner(timeout=args.timeout)
        try:
            results = scanner.scan_network(args.target, ports)
            scanner.print_results(results)
        except Exception as e:
            print(f"Error during scan: {e}")
    elif args.command == "packetmaster":
        try:
            results = packetmaster.scan_targets(
                [args.target],  # Pass target as a list
                args.port,
                args.data,
                args.protocol,
                args.output_file,
            )
            # Print results if not saved to a file
            if not args.output_file:
                for result in results:
                    print(result)
        except Exception as e:
            print(f"Error during packet manipulation: {e}")
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
            print(f"Error: {e}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
