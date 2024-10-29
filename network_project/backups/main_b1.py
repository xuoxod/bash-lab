#!/usr/bin/python3

import argparse
import logging
import time
import ipaddress
from network_modules import (
    port_scanner,
    robust_nmap_scanner,  # Import the robust Nmap scanner
    scapy_port_scanner,
    packetmaster,
)
from network_modules.helpers.parse_ports import parse_ports
from network_modules.traffic_interceptor import TrafficInterceptor

logging.basicConfig(level=logging.INFO)


def main():
    """
    NetSage Scanner: A versatile network scanning and analysis tool.

    NetSage Scanner empowers you to explore your network with a suite of powerful tools,
    including port scanning, packet manipulation, and traffic interception.

    Port Scanning:
    - Uncover open ports and services running on target hosts.
    - Choose from multiple scanning methods:
        - Nmap: Leverage the industry-standard Nmap scanner for comprehensive results.
        - Socket: Utilize Python sockets for a lightweight and efficient scan.
        - Scapy: Employ the Scapy library for crafting and sending custom packets,
          providing granular control over network interactions.

    Packet Manipulation:
    - Craft and send custom network packets using various protocols (TCP, UDP, ICMP).
    - Probe network services, test firewall rules, and simulate network traffic.

    Traffic Interception:
    - Reroute traffic from a target on your local network to your machine using ARP spoofing.
    - Analyze network traffic in real-time to gain insights into network communication patterns.

    NetSage Scanner provides a flexible and user-friendly interface, allowing you to tailor
    your network analysis to your specific needs.
    """
    parser = argparse.ArgumentParser(
        description="NetSage Scanner: A versatile network scanning and analysis tool.",
        epilog="""
        Examples:

        # Port Scanning:

        ## Nmap:
        - Scan a single IP using Nmap with default settings (OS detection):
            python main.py nmap 192.168.1.1

        - Scan a range of IPs using Nmap with a SYN scan:
            python main.py nmap 192.168.1.10-192.168.1.20 -st SYN Scan (Stealth)

        - Scan specific ports on a host using Nmap with a comprehensive scan:
            python main.py nmap 192.168.1.100 -p 22,80,443 -st Comprehensive Scan (Intense)

        - Scan a network for vulnerabilities using Nmap:
            python main.py nmap 192.168.1.0/24 -st Vulnerability Scan

        ## Socket:
        - Scan a single IP using Python sockets with default ports and timeout:
            python main.py socket 192.168.1.1

        - Scan a range of IPs using Python sockets with custom ports and timeout:
            python main.py socket 192.168.1.0/24 -p 22,80,443 -t 1.5

        - Scan a network with increased threads for faster scanning:
            python main.py socket 192.168.1.0/24 -th 200

        - Scan a host with a longer timeout for slower connections:
            python main.py socket 192.168.1.100 -p 8080 -t 5.0

        ## Scapy:
        - Scan specific ports on a host using Scapy with a default timeout:
            python main.py scapy 192.168.1.100 -p 22,8080

        - Scan a range of IPs using Scapy with a longer timeout:
            python main.py scapy 192.168.1.1-192.168.1.254 -p 80,443 -t 3.0

        - Scan a network using Scapy for open ports:
            python main.py scapy 192.168.1.0/24 -p 22,80,443

        - Scan a host using Scapy with a shorter timeout for faster results:
            python main.py scapy 192.168.1.100 -p 80 -t 1.0

        # Packet Manipulation (PacketMaster):
        - Send an ICMP echo request to a target:
            python main.py packetmaster 192.168.1.1

        - Send a TCP SYN packet to a specific port:
            python main.py packetmaster 192.168.1.1 -p 80 -prot tcp

        - Send a UDP packet with custom data:
            python main.py packetmaster 192.168.1.1 -p 53 -prot udp -d "Hello, UDP!"

        - Send an ICMP echo request and save results to a file:
            python main.py packetmaster 192.168.1.1 -o icmp_results.csv

        # Traffic Interception:
        - Reroute traffic from a target IP:
            python main.py traffic-interceptor 192.168.1.100

        For more detailed help on a specific command, use:
        python main.py <command> -h
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
        help="Perform a port scan using the robust Nmap scanner.",
        parents=[common_port_scan_args],
    )
    nmap_parser.add_argument(
        "-st",
        "--scan-type",
        choices=robust_nmap_scanner.SCAN_TYPES.keys(),
        default=robust_nmap_scanner.DEFAULT_SCAN_TYPE,
        help=f"""
        Type of Nmap scan to perform. 
        Choose from the following options (default: {robust_nmap_scanner.DEFAULT_SCAN_TYPE}):

        {', '.join(robust_nmap_scanner.SCAN_TYPES.keys())}
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
        scanner = robust_nmap_scanner.RobustNmapScanner(
            targets=args.target, ports=args.ports, scan_type=args.scan_type
        )
        scanner.print_results()

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
            # Expand the target if it's a CIDR range
            if "/" in args.target:
                target_ips = [
                    str(ip) for ip in ipaddress.ip_network(args.target).hosts()
                ]
            else:
                target_ips = [args.target]
            results = scanner.scan_network(target_ips, ports)
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
