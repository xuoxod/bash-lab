#!/usr/bin/python3
import socket
import csv
import os
from typing import List, Dict, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from scapy.all import *

from network_modules.helpers.colors import TextColors
from network_modules.helpers.utils import _validate_target


# Predefined common protocols
COMMON_PROTOCOLS = ["tcp", "udp", "icmp"]

# Maximum number of threads for concurrent scans
MAX_THREADS = 20  # You can adjust this based on your system and network


def _has_root_privileges() -> bool:
    """Checks if the script is running with root privileges."""
    return os.geteuid() == 0


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
    dst_ip: str,
    dst_port: int = None,
    payload: str = None,
    protocol: str = "icmp",
) -> Tuple[Dict, str]:
    """Sends a custom packet and returns a dictionary containing the results."""
    _validate_target(dst_ip)
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
        packet = IP(dst=dst_ip) / TCP(dport=dst_port, flags="S")  # SYN flag for reply
    elif protocol.lower() == "udp":
        packet = IP(dst=dst_ip) / UDP(dport=dst_port)
    elif protocol.lower() == "icmp":
        packet = IP(dst=dst_ip) / ICMP()
    else:
        return (
            output_data,
            f"{TextColors.FAIL}Error: Invalid protocol specified. Choose from: {', '.join(COMMON_PROTOCOLS)}{TextColors.ENDC}",
        )

    # Add payload if provided
    if payload:
        packet = packet / Raw(load=payload.encode())

    # Send the packet and receive response
    # print(
    #     f"{TextColors.OKGREEN}Sending {protocol.upper()} packet to {dst_ip}:{dst_port}...{TextColors.ENDC}"
    # )
    send_recv = sr1(packet, timeout=2, verbose=False)  # Send and receive 1 packet

    # --- Output Handling ---
    if send_recv:
        # print(
        #     f"{TextColors.OKGREEN}Response from {send_recv[IP].src}:{TextColors.ENDC}"
        # )
        # print(send_recv.show())  # Print detailed response to console

        # --- Prepare Data for Output ---
        unique_id = _get_mac_address(dst_ip)
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
        print(f"{TextColors.OKGREEN}[+] Results saved to {filename}{TextColors.ENDC}")
    except Exception as e:
        print(f"{TextColors.FAIL}Error saving output to CSV: {e}{TextColors.ENDC}")


def scan_targets(
    targets: List[str], port: int, data: str, protocol: str, output_file: str = None
) -> List[Dict]:
    """Scans multiple targets concurrently and optionally saves the results to a CSV file."""
    if not _has_root_privileges():
        print(
            f"{TextColors.FAIL}Error: This command requires root privileges. Please run as root or using sudo.{TextColors.ENDC}"
        )
        return []

    all_results = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [
            executor.submit(_send_custom_packet, target, port, data, protocol)
            for target in targets
        ]

        for future in as_completed(futures):
            result, error_msg = future.result()
            if error_msg:
                print(error_msg)
            else:
                all_results.append(result)

    if output_file:
        _save_to_csv(all_results, output_file)

    return all_results
