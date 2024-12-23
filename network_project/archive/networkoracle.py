#!/usr/bin/python3

import argparse
import socket
import re
import csv
import os
from typing import List, Dict, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import argparse  # Import argparse

# trunk-ignore(ruff/F403)
from scapy.all import *
from scapy.all import (
    IP,
    TCP,
    UDP,
    ICMP,
    Raw,
    sr1,
    DNS,
    DNSQR,
    Packet,
    sr,
    QueryAnswer,
)  # Import sr for ICMP
from helpers.utils import Utils


# ANSI escape codes for text coloring - A Vibrant Palette
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

    # Brighter Colors for NetworkOracle
    BRIGHT_RED = "\033[1;31m"
    BRIGHT_GREEN = "\033[1;32m"
    BRIGHT_YELLOW = "\033[1;33m"
    BRIGHT_BLUE = "\033[1;34m"
    BRIGHT_MAGENTA = "\033[1;35m"
    BRIGHT_CYAN = "\033[1;36m"
    WHITE = "\033[1;37m"  # Added white for clarity


class NetworkOracle:
    """
    An advanced network analysis tool that crafts, sends, and interprets custom network packets.
    """

    # Class-level attributes (constants)
    COMMON_PROTOCOLS = [
        "tcp",
        "udp",
        "icmp",
        "dns",
        "http",
        "https",
        "ftp",
        "ssh",
        "smtp",
        "telnet",
    ]
    MAX_THREADS = 20  # Adjustable based on system and network

    def __init__(self):
        """Initializes the NetworkOracle object."""
        self.output_data = []  # Store results for potential CSV output

    def _send_custom_packet(
        self,
        dst_ip: str,
        dst_port: int = None,
        payload: str = None,
        protocol: str = "icmp",
        timeout: int = 2,
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

        # Protocol to Port Mapping
        protocol_ports = {
            "tcp": 80,
            "udp": 53,
            "dns": 53,  # DNS can use both TCP and UDP
            "http": 80,
            "https": 443,
            "ftp": 21,
            "ssh": 22,
            "smtp": 25,
            "telnet": 23,
            "icmp": 0,  # ICMP doesn't use ports
        }

        # Determine port if not provided
        if dst_port is None:
            dst_port = protocol_ports.get(protocol.lower(), 0)

        # Create packet based on selected protocol
        if protocol.lower() == "tcp":
            packet = IP(dst=dst_ip) / TCP(dport=dst_port, flags="S")
        elif protocol.lower() == "udp":
            packet = IP(dst=dst_ip) / UDP(dport=dst_port)
        elif protocol.lower() == "icmp":
            packet = IP(dst=dst_ip) / ICMP()
        elif protocol.lower() == "dns":
            # Example DNS query for "google.com"
            packet = (
                IP(dst=dst_ip)
                / UDP(dport=dst_port)
                / DNS(rd=1, qd=DNSQR(qname="google.com"))
            )
        elif protocol.lower() == "http":
            # Example HTTP GET request
            packet = (
                IP(dst=dst_ip)
                / TCP(dport=dst_port)
                / "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(dst_ip)
            )
        elif protocol.lower() == "https":
            # Example HTTPS GET request (TLS handshake will likely fail)
            packet = (
                IP(dst=dst_ip)
                / TCP(dport=dst_port)
                / "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(dst_ip)
            )
        elif protocol.lower() == "ftp":
            # Example FTP initial connection request
            packet = IP(dst=dst_ip) / TCP(dport=dst_port, flags="S")
        elif protocol.lower() == "ssh":
            # Example SSH version string (initial handshake)
            packet = (
                IP(dst=dst_ip)
                / TCP(dport=dst_port, flags="S")
                / "SSH-2.0-OpenSSH_8.2p1"
            )
        elif protocol.lower() == "smtp":
            # Example SMTP EHLO command
            packet = (
                IP(dst=dst_ip) / TCP(dport=dst_port, flags="S") / "EHLO example.com\r\n"
            )
        elif protocol.lower() == "telnet":
            # Example Telnet initial connection request
            packet = IP(dst=dst_ip) / TCP(dport=dst_port, flags="S")
        else:
            return (
                output_data,
                f"{TextColors.FAIL}Error: Invalid protocol specified. Choose from: {', '.join(self.COMMON_PROTOCOLS)}{TextColors.ENDC}",
            )

        # Add payload if provided
        if payload:
            packet = packet / Raw(load=payload.encode())

        # Send the packet and receive response
        if protocol.lower() == "icmp":
            # Use sr() for ICMP to get both request and reply
            send_recv = sr(packet, timeout=timeout, verbose=False)
            send_recv = send_recv[0][0]  # Get the first sent/received pair
        else:
            send_recv = sr1(packet, timeout=timeout, verbose=False)

        # --- Output Handling (will be significantly enhanced) ---
        if send_recv:
            output_data = self._analyze_response(send_recv, protocol)
            return output_data, ""
        else:
            return (
                output_data,
                f"{TextColors.WARNING}No response received from {dst_ip}:{dst_port}{TextColors.ENDC}",
            )

    def _analyze_response(self, response: Packet, protocol: str) -> Dict:
        """Analyzes the response packet and extracts relevant information."""
        analysis = {}  # Initialize an empty dictionary to store analysis results

        # --- Handle ICMP responses (QueryAnswer objects) ---
        if isinstance(response, QueryAnswer):
            # Get the received packet from the answer
            received_packet = response.answer

            if received_packet.haslayer(IP):
                analysis["Target IP"] = received_packet[IP].dst
                analysis["Source IP"] = received_packet[IP].src
            analysis["Protocol"] = protocol.upper()
            analysis.update(self._analyze_icmp_response(received_packet))
            return analysis

        # --- Handle other protocol responses (Packet objects) ---
        if response.haslayer(IP):  # Check if IP layer exists
            analysis["Target IP"] = response[IP].dst
            analysis["Source IP"] = response[IP].src
        analysis["Protocol"] = protocol.upper()

        # --- Protocol-Specific Analysis (to be implemented) ---
        if protocol.lower() == "tcp":
            analysis.update(self._analyze_tcp_response(response))
        elif protocol.lower() == "udp":
            udp_result = self._analyze_udp_response(response)
            if udp_result:  # Check if udp_result is not None
                analysis.update(udp_result)
        elif protocol.lower() == "icmp":
            analysis.update(self._analyze_icmp_response(response))
        elif protocol.lower() == "dns":
            analysis.update(self._analyze_dns_response(response))
        elif protocol.lower() == "http":
            analysis.update(self._analyze_http_response(response))
        elif protocol.lower() == "https":
            analysis.update(self._analyze_https_response(response))
        elif protocol.lower() == "ftp":
            analysis.update(self._analyze_ftp_response(response))
        elif protocol.lower() == "ssh":
            analysis.update(self._analyze_ssh_response(response))
        elif protocol.lower() == "smtp":
            analysis.update(self._analyze_smtp_response(response))
        elif protocol.lower() == "telnet":
            analysis.update(self._analyze_telnet_response(response))

        return analysis

    def _analyze_tcp_response(self, response: Packet) -> Dict:
        """Analyzes a TCP response packet."""
        tcp_analysis = {}
        tcp_flags = response[TCP].flags

        # --- TCP Flag Analysis ---
        tcp_analysis["TCP Flags"] = tcp_flags
        if "S" in tcp_flags and "A" in tcp_flags:  # SYN-ACK
            tcp_analysis["Status"] = f"{TextColors.BRIGHT_GREEN}Open{TextColors.ENDC}"
        elif "R" in tcp_flags:  # RST
            tcp_analysis["Status"] = f"{TextColors.BRIGHT_RED}Closed{TextColors.ENDC}"
        else:
            tcp_analysis["Status"] = f"{TextColors.WARNING}Unknown{TextColors.ENDC}"

        # --- Payload Analysis (if present) ---
        if response.haslayer(Raw):
            payload = response[Raw].load.decode("utf-8", errors="replace")
            tcp_analysis["Payload"] = payload[:100]  # Truncate for display

        return tcp_analysis

    def _analyze_udp_response(self, response: Packet) -> Dict:
        """Analyzes a UDP response packet."""
        udp_analysis = {}

        if response.haslayer(UDP):
            udp_analysis["UDP Source Port"] = response[UDP].sport
            udp_analysis["UDP Destination Port"] = response[UDP].dport

            # --- Payload Analysis (if present) ---
            if response.haslayer(Raw):
                payload = response[Raw].load
                udp_analysis["Payload Length"] = len(payload)
                try:
                    udp_analysis["Payload (ASCII)"] = payload.decode("ascii", "ignore")
                except UnicodeDecodeError:
                    udp_analysis["Payload (Hex)"] = payload.hex()

                # --- DNS Analysis (Port 53) ---
                if response[UDP].sport == 53 or response[UDP].dport == 53:
                    try:
                        dns_response = DNS(payload)
                        udp_analysis["DNS Response Code"] = dns_response.rcode
                        if dns_response.an:
                            resolved_ips = [
                                answer.rdata
                                for answer in dns_response.an
                                if answer.type == 1  # A record
                            ]
                            udp_analysis["Resolved IPs"] = resolved_ips
                    except Exception as e:
                        udp_analysis["DNS Analysis Error"] = f"Error: {e}"

                # --- DHCP Analysis (Ports 67, 68) ---
                elif (
                    response[UDP].sport == 67
                    or response[UDP].sport == 68
                    or response[UDP].dport == 67
                    or response[UDP].dport == 68
                ):
                    try:
                        # DHCP analysis is more complex and requires parsing
                        # the DHCP options. You'll need to implement this based
                        # on the DHCP protocol structure.
                        udp_analysis["DHCP Analysis"] = "To be implemented"
                    except Exception as e:
                        udp_analysis["DHCP Analysis Error"] = f"Error: {e}"

    def _analyze_icmp_response(self, response: Packet) -> Dict:
        """Analyzes an ICMP response packet."""
        icmp_analysis = {}
        if response.haslayer(ICMP):
            icmp_analysis["ICMP Type"] = response[ICMP].type
            icmp_analysis["ICMP Code"] = response[ICMP].code
            # ... (Add more ICMP analysis as needed)
        return icmp_analysis

    def _analyze_dns_response(self, response: Packet) -> Dict:
        """Analyzes a DNS response packet."""
        dns_analysis = {}
        if response.haslayer(DNS):
            dns_analysis["DNS Response Code"] = response[DNS].rcode

            # --- Resolved IPs (A records) ---
            if response[DNS].an:
                resolved_ips = []
                for answer in response[DNS].an:
                    if answer.type == 1:  # A record
                        resolved_ips.append(answer.rdata)
                dns_analysis["Resolved IPs"] = resolved_ips

            # --- Other Record Types ---
            # (Add logic to extract CNAME, MX, TXT, etc. records)

        return dns_analysis

    def _analyze_http_response(self, response: Packet) -> Dict:
        """Analyzes an HTTP response packet."""
        http_analysis = {}
        if response.haslayer(TCP) and (
            response[TCP].dport == 80 or response[TCP].dport == 443
        ):
            http_data = response[TCP].payload.load.decode("utf-8", errors="replace")

            # --- Status Code ---
            status_code_match = re.search(r"HTTP/1\.[01] (\d{3}) (.*)", http_data)
            if status_code_match:
                http_analysis["Status Code"] = status_code_match.group(1)
                http_analysis["Status Message"] = status_code_match.group(2)

            # --- Headers ---
            headers = http_data.split("\r\n")
            for header in headers:
                if ":" in header:
                    key, value = header.split(":", 1)
                    http_analysis[key.strip()] = value.strip()

            # --- Title (if HTML) ---
            if (
                "Content-Type" in http_analysis
                and "text/html" in http_analysis["Content-Type"]
            ):
                title_match = re.search(
                    r"<title>(.*?)</title>", http_data, re.IGNORECASE
                )
                if title_match:
                    http_analysis["Title"] = title_match.group(1)

        return http_analysis

    def _analyze_https_response(self, response: Packet) -> Dict:
        """Analyzes an HTTPS response packet (basic checks)."""
        https_analysis = {}
        if response.haslayer(TCP) and response[TCP].dport == 443:
            https_analysis["Destination Port"] = response[TCP].dport

            # --- Try to decode the initial part of the response (might be TLS handshake) ---
            try:
                https_data = response[TCP].payload.load.decode(
                    "utf-8", errors="replace"
                )

                # --- Headers ---
                headers = https_data.split("\r\n")
                for header in headers:
                    if ":" in header:
                        key, value = header.split(":", 1)
                        https_analysis[key.strip()] = value.strip()

            except Exception as e:
                https_analysis["Error"] = f"Could not decode response: {e}"

        return https_analysis

    def _analyze_ftp_response(self, response: Packet) -> Dict:
        """Analyzes an FTP response packet."""
        ftp_analysis = {}
        if response.haslayer(TCP) and response[TCP].dport == 21:
            ftp_data = response[TCP].payload.load.decode("utf-8", errors="replace")
            match = re.match(r"(\d{3}) (.*)", ftp_data)
            if match:
                ftp_analysis["FTP Response Code"] = match.group(1)
                ftp_analysis["FTP Response Message"] = match.group(2)
        return ftp_analysis

    def _analyze_ssh_response(self, response: Packet) -> Dict:
        """Analyzes an SSH response packet."""
        ssh_analysis = {}
        if response.haslayer(TCP) and response[TCP].dport == 22:
            ssh_data = response[TCP].payload.load.decode("utf-8", errors="replace")
            match = re.match(r"SSH-(\d\.\d)-(.+)", ssh_data)
            if match:
                ssh_analysis["SSH Version"] = match.group(1)
                ssh_analysis["SSH Server"] = match.group(2)
        return ssh_analysis

    def _analyze_smtp_response(self, response: Packet) -> Dict:
        """Analyzes an SMTP response packet."""
        smtp_analysis = {}
        if response.haslayer(TCP) and response[TCP].dport == 25:
            smtp_data = response[TCP].payload.load.decode("utf-8", errors="replace")
            match = re.match(r"(\d{3}) (.*)", smtp_data)
            if match:
                smtp_analysis["SMTP Response Code"] = match.group(1)
                smtp_analysis["SMTP Response Message"] = match.group(2)
        return smtp_analysis

    def _analyze_telnet_response(self, response: Packet) -> Dict:
        """Analyzes a Telnet response packet."""
        telnet_analysis = {}
        if response.haslayer(TCP) and response[TCP].dport == 23:
            telnet_data = response[TCP].payload.load

            # --- Look for Telnet Control Codes ---
            for i in range(len(telnet_data) - 1):
                if telnet_data[i] == 255:  # IAC (Interpret as Command)
                    command = telnet_data[i + 1]
                    if command == 251:  # WILL (option negotiation)
                        option = telnet_data[i + 2]
                        telnet_analysis[f"WILL Option {option}"] = True
                    elif command == 252:  # WON'T
                        option = telnet_data[i + 2]
                        telnet_analysis[f"WON'T Option {option}"] = True
                    # ... (Add more Telnet command handling)

        return telnet_analysis

    def scan_targets(
        self,
        targets: List[str],
        port: int = None,
        data: str = None,
        protocol: str = "icmp",
        output_file: str = None,
    ) -> List[Dict]:
        """Scans multiple targets concurrently and optionally saves the results to a CSV file."""

        # --- Root Privilege Check ---
        if not os.geteuid() == 0:
            print(
                f"{TextColors.FAIL}Error: This command requires root privileges. Please run as root or using sudo.{TextColors.ENDC}"
            )
            return []  # Return an empty list if not root

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
            self._save_to_csv(all_results, output_file)  # Implement _save_to_csv

        return all_results

    def _save_to_csv(self, data: List[Dict], filename: str = None):
        """Saves the output data to a CSV file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            filename = f"networkoracle_output_{timestamp}.csv"
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


def main():
    """Handles command-line arguments and runs NetworkOracle."""

    # --- Create the main parser ---
    parser = argparse.ArgumentParser(
        description="""
        NetworkOracle: An advanced network analysis tool for crafting, sending, 
        and interpreting custom network packets.

        This tool allows you to probe network devices and services using various 
        protocols, analyze responses, and gain insights into network behavior. 
        It supports TCP, UDP, ICMP, DNS, HTTP, HTTPS, FTP, SSH, SMTP, and Telnet.

        NetworkOracle is designed for network administrators, security professionals, 
        and anyone interested in understanding network communication at a deeper level.
        """,
        epilog="""
        Examples:

        1. Basic ICMP Scan:
           python networkoracle.py -t 192.168.1.10

        2. TCP SYN Scan on Port 80:
           python networkoracle.py -t 192.168.1.10 -p 80 -prot tcp

        3. DNS Query for google.com:
           python networkoracle.py -t 8.8.8.8 -prot dns

        4. HTTP GET Request with Custom Payload:
           python networkoracle.py -t www.example.com -prot http -d "GET /test.html HTTP/1.1\\r\\nHost: www.example.com\\r\\n\\r\\n"

        5. Scan Multiple Targets and Save to CSV:
           python networkoracle.py -t 192.168.1.10,192.168.1.20 -prot icmp -o scan_results.csv
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,  # Preserve formatting
    )

    # --- Required Arguments ---
    parser.add_argument(
        "-t",
        "--targets",
        required=True,
        help="""
        Comma-separated list of target IP addresses or hostnames. 
        Example: 192.168.1.10,192.168.1.20,www.example.com
        """,
    )

    # --- Optional Arguments ---
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="""
        Destination port (optional). If not provided, a default port will be used 
        based on the selected protocol.
        """,
    )
    parser.add_argument(
        "-d",
        "--data",
        help="""
        Payload data to send with the packet (optional). The format of the payload 
        depends on the selected protocol. 
        
        Examples:
        - HTTP: "GET /index.html HTTP/1.1\\\\r\\\\nHost: www.example.com\\\\r\\\\n\\\\r\\\\n"
        - DNS: (No data needed, the tool will craft a DNS query)
        - ICMP: (No data needed)
        """,
    )
    parser.add_argument(
        "-prot",
        "--protocol",
        default="icmp",
        choices=NetworkOracle.COMMON_PROTOCOLS,
        help="""
        Network protocol to use. Choose from: 
          tcp, udp, icmp, dns, http, https, ftp, ssh, smtp, telnet 
        (default: icmp)
        """,
    )
    parser.add_argument(
        "-o",
        "--output",
        help="""
        Output CSV filename (optional). If provided, the scan results will be 
        saved to a CSV file with the specified name.
        """,
    )

    # --- Parse the arguments ---
    args = parser.parse_args()

    # --- Resolve domain names to IP addresses ---
    resolved_targets = []
    for target in args.targets.split(","):
        try:
            # Try to convert the target to an IP address directly
            socket.inet_aton(target)
            resolved_targets.append(target)  # It's already an IP address
        except socket.error:
            # If it's not an IP address, try to resolve it as a domain name
            try:
                ip_address = socket.gethostbyname(target)
                resolved_targets.append(ip_address)
                print(f"Resolved {target} to {ip_address}")
            except socket.gaierror:
                print(
                    f"{TextColors.FAIL}Error: Could not resolve {target}{TextColors.ENDC}"
                )

    # --- Create NetworkOracle instance and run scan ---
    oracle = NetworkOracle()
    results = oracle.scan_targets(
        targets=resolved_targets,  # Use the resolved targets
        port=args.port,
        data=args.data,
        protocol=args.protocol,
        output_file=args.output,
    )

    # --- Print Results to Console ---
    if results:
        for result in results:
            print("-" * 50)
            for key, value in result.items():
                print(f"{TextColors.OKBLUE}{key}:{TextColors.ENDC} {value}")
    else:
        print(f"{TextColors.WARNING}No results found.{TextColors.ENDC}")


if __name__ == "__main__":
    main()
