#!/usr/bin/python3
import socket
import csv
import os
from typing import List, Dict, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import argparse  # Import argparse

from scapy.all import *
from helpers.utils import Utils

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
    # New colors
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    LIGHT_YELLOW = "\033[1;33m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_MAGENTA = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"


class PacketMaster:
    """
    A class for crafting and sending custom network packets, primarily using Scapy.
    """

    # Class-level attributes (constants)
    COMMON_PROTOCOLS = ["tcp", "udp", "icmp"]
    MAX_THREADS = 20  # Adjustable based on system and network

    def __init__(self):
        """Initializes the PacketMaster object."""
        self.output_data = []  # Store results for potential CSV output

    @staticmethod
    def _has_root_privileges() -> bool:
        """Checks if the script is running with root privileges."""
        return os.geteuid() == 0

    @staticmethod
    def _get_mac_address(ip_address: str) -> Union[str, None]:
        """Tries to get the MAC address for an IP address using ARP."""
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
                timeout=2,
                verbose=False,
            )
            if ans:
                return ans[0][1].hwsrc
            else:
                return None
        except Exception as e:
            print(f"{TextColors.FAIL}Error getting MAC address: {e}{TextColors.ENDC}")
            return None

    def _send_custom_packet(
        self,
        dst_ip: str,
        dst_port: int = None,
        payload: str = None,
        protocol: str = "icmp",
    ) -> Tuple[Dict, str]:
        """Sends a custom packet and returns a dictionary containing the results."""
        Utils.validate_target(dst_ip)
        output_data = {}
        try:
            # Validate IP address
            socket.inet_aton(dst_ip)
        except socket.error:
            return (
                output_data,
                f"{TextColors.FAIL}Error: Invalid destination IP address: {dst_ip}{TextColors.ENDC}",
            )

        # Determine port if not provided
        if dst_port is None:
            if protocol.lower() == "tcp":
                dst_port = 80  # Default to port 80 (HTTP) for TCP
            elif protocol.lower() == "udp":
                dst_port = 53  # Default to port 53 (DNS) for UDP
            else:
                dst_port = 0  # ICMP doesn't use a port number

        # Create packet based on selected protocol
        if protocol.lower() == "tcp":
            packet = IP(dst=dst_ip) / TCP(
                dport=dst_port, flags="S"
            )  # SYN flag for reply
        elif protocol.lower() == "udp":
            packet = IP(dst=dst_ip) / UDP(dport=dst_port)
        elif protocol.lower() == "icmp":
            packet = IP(dst=dst_ip) / ICMP()
        else:
            return (
                output_data,
                f"{TextColors.FAIL}Error: Invalid protocol specified. Choose from: {', '.join(self.COMMON_PROTOCOLS)}{TextColors.ENDC}",
            )

        # Add payload if provided
        if payload:
            packet = packet / Raw(load=payload.encode())

        # Send the packet and receive response
        send_recv = sr1(packet, timeout=2, verbose=False)  # Send and receive 1 packet

        # --- Output Handling ---
        if send_recv:
            # --- Prepare Data for Output ---
            unique_id = self._get_mac_address(dst_ip)
            if not unique_id:
                unique_id = dst_ip  # Use IP if MAC is not available

            # --- Protocol Mapping ---
            protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
            protocol_name = protocol_map.get(send_recv[IP].proto, "Unknown")

            # --- Type of Service (TOS) Mapping (Example) ---
            tos_map = {
                0: "Routine",
                1: "Priority",
                2: "Immediate",
                # ... Add more TOS values and descriptions as needed
            }
            tos_description = tos_map.get(send_recv[IP].tos, "Unknown")

            # --- Data for File Output ---
            output_data = {
                "Target": unique_id,
                "Source IP": send_recv[IP].src,
                "Destination IP": send_recv[IP].dst,
                "Protocol (Number)": send_recv[IP].proto,
                "Protocol (Name)": protocol_name,
                "Checksum": send_recv[IP].chksum,
                "ID": send_recv[IP].id,
                "Length": send_recv[IP].len,
                "Type of Service (Number)": send_recv[IP].tos,
                "Type of Service (Description)": tos_description,
                "Packet Type": (
                    send_recv.getlayer(1).sprintf("%TCP.flags%")
                    if protocol.lower() == "tcp"
                    else send_recv.getlayer(1).type
                ),
            }
            return output_data, ""
        else:
            return (
                output_data,
                f"{TextColors.WARNING}No response received from {dst_ip}:{dst_port}{TextColors.ENDC}",
            )

    def scan_targets(
        self,
        targets: List[str],
        port: int = None,
        data: str = None,
        protocol: str = "icmp",
        output_file: str = None,
    ) -> List[Dict]:
        """Scans multiple targets concurrently and optionally saves the results to a CSV file."""
        if not self._has_root_privileges():
            print(
                f"{TextColors.FAIL}Error: This command requires root privileges. Please run as root or using sudo.{TextColors.ENDC}"
            )
            return []

        all_results = []
        with ThreadPoolExecutor(max_workers=self.MAX_THREADS) as executor:
            futures = [
                executor.submit(self._send_custom_packet, target, port, data, protocol)
                for target in targets
            ]

            for future in as_completed(futures):
                result, error_msg = future.result()
                if error_msg:
                    print(error_msg)
                else:
                    all_results.append(result)

        if output_file:
            self._save_to_csv(all_results, output_file)

        return all_results

    @staticmethod
    def _save_to_csv(data: List[Dict], filename: str = None):
        """Saves the output data to a CSV file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            filename = f"packetmaster_output_{timestamp}.csv"
        try:
            with open(filename, "w", newline="") as csvfile:
                fieldnames = data[0].keys() if data else []
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
            print(
                f"{TextColors.OKGREEN}[+] Results saved to {filename}{TextColors.ENDC}"
            )
        except Exception as e:
            print(f"{TextColors.FAIL}Error saving output to CSV: {e}{TextColors.ENDC}")


if __name__ == "__main__":
    """Handles command-line arguments and runs the PacketMaster."""
    parser = argparse.ArgumentParser(
        description="Craft and send custom network packets.",
        epilog="Example: python packetmaster.py -t 192.168.1.1,192.168.1.10 -p 80 -d 'Hello' -prot tcp -o output.csv",
    )
    parser.add_argument(
        "-t",
        "--targets",
        required=True,
        help="Comma-separated list of target IP addresses.",
    )
    parser.add_argument("-p", "--port", type=int, help="Destination port (optional).")
    parser.add_argument("-d", "--data", help="Payload data (optional).")
    parser.add_argument(
        "-prot",
        "--protocol",
        default="icmp",
        choices=PacketMaster.COMMON_PROTOCOLS,
        help="Protocol to use (default: icmp).",
    )
    parser.add_argument("-o", "--output", help="Output CSV filename (optional).")

    args = parser.parse_args()

    # --- Create PacketMaster instance and run scan ---
    packet_master = PacketMaster()
    results = packet_master.scan_targets(
        targets=args.targets.split(","),  # Split comma-separated targets
        port=args.port,
        data=args.data,
        protocol=args.protocol,
        output_file=args.output,
    )

    # --- Print Results to Console ---
    if results:
        for result in results:
            print("-" * 40)
            for key, value in result.items():
                print(f"{TextColors.OKBLUE}{key}:{TextColors.ENDC} {value}")
    else:
        print(f"{TextColors.WARNING}No results found.{TextColors.ENDC}")
