#!/usr/bin/python3

import argparse
import logging
import os
from scapy.all import *
from helpers.packetmaker import PacketMaker, NoIPError, InterfaceError

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(
        description="""
    A comprehensive network tool for packet crafting, network scanning, and DNS requests.
    Perform various types of scans, craft custom packets, and query DNS servers with ease.
    """,
        epilog="""
    Examples:

    Craft a UDP packet to 192.168.1.100:
        ./netcraft.py -cu --dst-ip 192.168.1.100 --dst-port 50000 --payload "Hello UDP"

    Perform an ACK scan on ports 80, 443, and 8080:
        ./netcraft.py -a 192.168.1.100 --ports 80,443,8080

    Perform a DNS request for google.com:
        ./netcraft.py --dns-server 8.8.8.8 -d google.com -rt A

    Display system information (default): 
        ./netcraft.py       OR   ./netcraft.py -si

    More options available. Use --help for individual command help.
    """,
        formatter_class=argparse.RawDescriptionHelpFormatter,  # Preserve formatting
    )

    parser.add_argument("-i", "--interface", help="Network interface to use")

    # Packet Crafting Options
    packet_group = parser.add_argument_group("Packet Crafting")

    # Add missing arguments
    packet_group.add_argument("--dst-ip", help="Destination IP address")

    packet_group.add_argument(
        "--src-port", type=int, help="Source port"
    )  # Type enforcement

    packet_group.add_argument(
        "--dst-port", type=int, help="Destination port"
    )  # Type enforcement

    packet_group.add_argument("--payload", help="Packet payload")

    packet_group.add_argument(
        "--marker", help="Payload marker to prepend"
    )  # Add marker

    packet_group.add_argument(
        "-cu", "--craft-udp", action="store_true", help="Craft a UDP packet"
    )

    packet_group.add_argument(
        "-ct", "--craft-tcp", action="store_true", help="Craft a TCP packet"
    )

    packet_group.add_argument(
        "-ci", "--craft-icmp", action="store_true", help="Craft an ICMP packet"
    )

    # ... (Add more arguments for packet crafting options like destination IP, ports, payload, etc.)

    # Scanning Options
    scan_group = parser.add_argument_group("Network Scans")

    scan_group.add_argument(
        "-a", "--ack-scan", metavar="TARGET_IP", help="Perform an ACK scan"
    )

    scan_group.add_argument(
        "-x", "--xmas-scan", metavar="TARGET_IP", help="Perform a Xmas scan"
    )

    scan_group.add_argument(
        "--ports", help="Comma-separated list of ports (e.g., 80,443,22)"
    )

    scan_group.add_argument(
        "-ps", "--protocol-scan", metavar="TARGET_IP", help="Perform a protocol scan"
    )

    scan_group.add_argument(
        "-ap", "--arp-ping", metavar="TARGET_NETWORK", help="Perform an ARP ping"
    )

    scan_group.add_argument(
        "-ip", "--icmp-ping", metavar="TARGET_NETWORK", help="Perform an ICMP ping"
    )

    scan_group.add_argument(
        "-tp", "--tcp-ping", metavar="TARGET_NETWORK", help="Perform a TCP ping"
    )

    scan_group.add_argument(
        "-up", "--udp-ping", metavar="TARGET_NETWORK", help="Perform a UDP ping"
    )

    # DNS Request options
    dns_group = parser.add_argument_group("DNS Requests")
    dns_group.add_argument("-dns", "--dns-server", help="DNS server IP address")
    dns_group.add_argument("-d", "--domain", help="Domain name to query")
    dns_group.add_argument(
        "-rt",
        "--record-type",
        default="A",
        help="Record type (e.g., A, AAAA, MX, etc.)",
    )

    # System Information
    sys_group = parser.add_argument_group("System Information")
    sys_group.add_argument(
        "-si", "--sysinfo", action="store_true", help="Display system information"
    )

    args = parser.parse_args()

    try:
        packet_maker = PacketMaker(interface=args.interface)

        # Packet Crafting
        if args.craft_udp:
            try:  # Inner try-except for packet crafting/sending
                packet = packet_maker.craft_udp_packet(
                    dst_ip=args.dst_ip,  # Use argparse arguments
                    src_port=args.src_port,
                    dst_port=args.dst_port,
                    payload=args.payload,
                    marker=args.marker,
                )
                send(packet, verbose=True)  # Send the packet using scapy.all.send
                print(packet.summary())
            except (TypeError, NoIPError) as e:
                print(f"Error crafting/sending UDP packet: {e}")

        elif args.craft_tcp:
            try:  # Inner try-except for packet crafting/sending
                packet = packet_maker.craft_tcp_packet(
                    dst_ip=args.dst_ip,  # Use argparse arguments
                    src_port=args.src_port,
                    dst_port=args.dst_port,
                    payload=args.payload,
                    marker=args.marker,
                )
                send(packet, verbose=True)  # Send the packet using scapy.all.send
                print(packet.summary())
            except (TypeError, NoIPError) as e:
                print(f"Error crafting/sending TCP packet: {e}")

        elif args.craft_icmp:
            try:  # Inner try-except for packet crafting/sending
                packet = packet_maker.craft_icmp_packet(
                    dst_ip=args.dst_ip,  # Use argparse arguments
                    payload=args.payload,
                    marker=args.marker,
                )
                send(packet, verbose=True)  # Send the packet using scapy.all.send
                print(packet.summary())
            except (TypeError, NoIPError) as e:
                print(f"Error crafting/sending ICMP packet: {e}")

        # Network Scanning (Add error handling and argument parsing for other scan types)
        elif args.ack_scan:
            try:
                ports = (
                    [int(p) for p in args.ports.split(",")] if args.ports else []
                )  # Port list
                packet_maker.ack_scan(args.ack_scan, ports=ports, verbose=True)
            except Exception as e:
                print(f"Error during ACK scan: {e}")

        elif args.xmas_scan:
            try:
                ports = [int(p) for p in args.ports.split(",")] if args.ports else []
                packet_maker.xmas_scan(
                    args.xmas_scan, ports, verbose=1
                )  # Example usage
            except Exception as e:
                print(f"Error during Xmas scan: {e}")

        elif args.xmas_scan:
            try:
                ports = [int(p) for p in args.ports.split(",")] if args.ports else []
                packet_maker.xmas_scan(
                    args.xmas_scan, ports, verbose=1
                )  # Example usage
            except Exception as e:
                print(f"Error during Xmas scan: {e}")

        elif args.protocol_scan:  # <-- INSERTION POINT
            try:
                packet_maker.ip_scan(args.protocol_scan, verbose=True)
            except Exception as e:  # More specific exception if possible
                print(f"Error during protocol scan: {e}")

        elif args.arp_ping:
            try:
                packet_maker.arp_ping(args.arp_ping, verbose=True)
            except Exception as e:
                print(f"Error during ARP ping: {e}")

        elif args.icmp_ping:  # Add icmp_ping handling
            try:
                packet_maker.icmp_ping(args.icmp_ping, verbose=True)
            except Exception as e:
                print(f"Error during ICMP ping: {e}")

        elif args.tcp_ping:  # Add tcp_ping handling
            try:
                packet_maker.tcp_ping(args.tcp_ping, verbose=True)  # Use args.dst_port?
            except Exception as e:
                print(f"Error during TCP ping: {e}")

        elif args.udp_ping:  # Add udp_ping handling
            try:
                packet_maker.udp_ping(args.udp_ping, verbose=True)  # Use args.dst_port?
            except Exception as e:
                print(f"Error during UDP ping: {e}")

        # DNS request.
        elif args.dns_server and args.domain:
            result = packet_maker.dns_request(
                args.dns_server, args.domain, args.record_type
            )
            if result:
                print(result)

        # System Information
        elif args.sysinfo:
            packet_maker.print_system_info()

        else:  # Default action: System Information (either explicit -si or no other args)
            packet_maker.print_system_info()

    except (InterfaceError, NoIPError) as e:
        print(f"Network configuration error: {e}")  # Handle outer errors


if __name__ == "__main__":
    main()
