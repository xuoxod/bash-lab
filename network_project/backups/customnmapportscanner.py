#!/usr/bin/python3

import subprocess
import threading
import ipaddress
from typing import List, Dict, Tuple
from xml.etree import ElementTree as ET
import csv  # Import for CSV saving

# Import Scapy
from scapy.all import ARP, Ether, srp


# ANSI escape codes for text coloring
class TextColors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


class CustomNmapScanner:
    # Predefined Nmap Scan Types (More Comprehensive)
    SCAN_TYPES = {
        "1": {"name": "SYN Scan (Stealth)", "arguments": "-sS"},
        "2": {"name": "TCP Connect Scan", "arguments": "-sT"},  # Added -sT
        "3": {"name": "UDP Scan", "arguments": "-sU"},
        "4": {"name": "FIN Scan (Stealth)", "arguments": "-sF"},
        "5": {"name": "NULL Scan (Stealth)", "arguments": "-sN"},
        "6": {"name": "Xmas Scan (Stealth)", "arguments": "-sX"},
        "7": {"name": "ACK Scan (Firewall Detection)", "arguments": "-sA"},
        "8": {"name": "Window Scan (Firewall Detection)", "arguments": "-sW"},
        "9": {"name": "Maimon Scan (Firewall Detection)", "arguments": "-sM"},
        "10": {"name": "Ping Scan (Host Discovery)", "arguments": "-sP"},
        "11": {"name": "OS Detection", "arguments": "-O"},
        "12": {"name": "Aggressive Scan", "arguments": "-A"},
    }

    # Predefined Common Ports
    COMMON_PORTS = {
        "1": {"name": "Top 10", "ports": "21,22,23,25,53,80,110,139,443,445"},
        "2": {"name": "Top 100", "ports": "1-100"},
        "3": {"name": "Top 1000", "ports": "1-1000"},
        "4": {"name": "All Ports", "ports": "1-65535"},
    }

    def __init__(self, targets: str, ports: str = None, scan_type: str = None):
        self.targets = self._parse_targets(targets)
        self.ports = self._parse_ports(ports) if ports else None
        self.arguments = self._get_scan_arguments(scan_type)
        self.scan_results = {}
        self.stop_event = threading.Event()

    def _parse_targets(self, target_input):
        targets = []
        for target in target_input.split(","):
            target = target.strip()
            try:
                ipaddress.ip_address(target)
                targets.append(target)
            except ValueError:
                try:
                    network = ipaddress.ip_network(target)
                    targets.extend([str(ip) for ip in network])
                except ValueError:
                    print(f"Invalid IP address or CIDR range: {target}")
        return targets

    def _parse_ports(self, ports: str) -> str:
        """Parses the port string into a comma-separated list of ports,
        validating and formatting for nmap.
        """
        valid_ports = []
        for port_str in ports.split(","):
            port_str = port_str.strip()  # Remove leading/trailing spaces
            if not port_str:  # Check for empty string after stripping
                continue  # Skip to the next port if it's empty

            if "-" in port_str:
                # Handle port ranges
                try:
                    start, end = map(int, port_str.split("-"))
                    if 1 <= start <= end <= 65535:
                        valid_ports.append(f"{start}-{end}")
                    else:
                        self.print_error(f"Invalid port range: {port_str}")
                except ValueError:
                    self.print_error(f"Invalid port range format: {port_str}")
            elif port_str.isdigit():  # Check if it's a number
                # Handle individual ports
                try:
                    port = int(port_str)
                    if 1 <= port <= 65535:
                        valid_ports.append(str(port))
                    else:
                        self.print_error(f"Invalid port number: {port}")
                except ValueError:
                    self.print_error(f"Invalid port format: {port_str}")
            else:
                self.print_error(f"Invalid port format: {port_str}")
        return ",".join(valid_ports)

    def _get_scan_arguments(self, scan_type: str) -> str:
        """Returns the nmap arguments based on the selected scan type."""
        if scan_type and scan_type in self.SCAN_TYPES:
            return self.SCAN_TYPES[scan_type]["arguments"]
        else:
            return "-T4 -F"  # Default scan arguments

    def _execute_nmap_scan(self, target):
        command = ["nmap"]

        if self.ports:
            self.arguments = ""  # Clear default arguments if ports are provided
            command.extend(["-p", self.ports])

        elif self.arguments:
            command.extend(self.arguments.split())

        command.append(target)

        try:
            nmap_process = subprocess.run(
                command, capture_output=True, text=True, check=True, timeout=188
            )

            if nmap_process.stderr:
                print(f"Nmap error for {target}: {nmap_process.stderr}")
                return nmap_process.stdout
        except subprocess.TimeoutExpired as e:
            print(f"Timeout error scanning {target}: {e}")
            return None
        except subprocess.CalledProcessError as e:
            print(f"Error scanning {target}: {e}")
            return None

    def _parse_nmap_output(self, xml_output, target):
        try:
            root = ET.fromstring(xml_output)

            for host in root.findall("host"):
                addresses = host.findall("address")
                for address_elem in addresses:
                    if address_elem.get("addr") == target:
                        # --- Hostname Extraction ---
                        hostname_element = host.find("hostnames/hostname")
                        hostname = (
                            hostname_element.get("name")
                            if hostname_element is not None
                            else "N/A"
                        )

                        # --- Port Information Extraction ---
                        port_info = []
                        ports = host.find("ports")
                        if ports is not None:
                            for port_elem in ports.findall("*"):
                                if port_elem.tag == "port":
                                    port_number = port_elem.get("portid")
                                    protocol = port_elem.get("protocol", "Unknown")
                                    state_element = port_elem.find("state")
                                    state = (
                                        state_element.get("state")
                                        if state_element is not None
                                        else "Unknown"
                                    )
                                    service = port_elem.find("service").get(
                                        "name", "Unknown"
                                    )

                                    port_info.append(
                                        {
                                            "port": port_number,
                                            "protocol": protocol,
                                            "state": state,
                                            "service": service,
                                        }
                                    )

                                elif port_elem.tag == "extraports":
                                    state = port_elem.get("state")
                                    count = int(port_elem.get("count"))
                                    print(
                                        f"{TextColors.WARNING}  {count} more ports in state: {state}{TextColors.ENDC}"
                                    )
                        else:
                            print(
                                f"{TextColors.WARNING}  No port information found.{TextColors.ENDC}"
                            )
                        return hostname, port_info  # Return hostname and port info
            print(f"{TextColors.WARNING}  Host not found in results.{TextColors.ENDC}")
            return "N/A", []  # Return default values if host not found
        except ET.ParseError as e:
            self.print_error(f"Error parsing Nmap output for {target}: {e}")
            return "N/A", []  # Return default values on parsing error

    def print_results(self) -> None:
        """Prints the scan results to the console."""
        for ip, (hostname, results) in self.scan_results.items():
            print(f"{TextColors.HEADER}Host: {hostname} ({ip}){TextColors.ENDC}")
            if results:
                print(
                    f"{TextColors.OKBLUE}  Port\tProtocol\tState\tService{TextColors.ENDC}"
                )
                for port_info in results:
                    print(
                        f"  {port_info['port']}/{port_info['protocol']}\t{port_info['state']}\t{port_info['service']}"
                    )
            else:
                print(f"  {TextColors.WARNING}No open ports found.{TextColors.ENDC}")
            print("-" * 40)

    def scan(self, targets: str):
        """Scans the specified targets and stores the results."""
        targets = self._parse_targets(targets)
        threads = []
        for target in targets:
            thread = threading.Thread(target=self._scan_target, args=(target,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        self.print_results()  # Print results after all threads finish

    def _scan_target(self, target):
        xml_output = self._execute_nmap_scan(target)
        if xml_output:
            hostname, open_ports = self._parse_nmap_output(xml_output, target)
            self.scan_results[target] = (hostname, open_ports)

    def print_status(self, message: str) -> None:
        """Prints a status message to the console."""
        print(f"{TextColors.OKBLUE}[*] {message}{TextColors.ENDC}")

    def print_error(self, message: str) -> None:
        """Prints an error message to the console."""
        print(f"{TextColors.FAIL}[!] {message}{TextColors.ENDC}")

    def print_warning(self, message: str) -> None:
        """Prints a warning message to the console."""
        print(f"{TextColors.WARNING}[!] {message}{TextColors.ENDC}")

    def stop(self):
        """Stops the scanner."""
        self.print_warning("Stopping the scanner...")
        self.stop_event.set()

    def save_results_to_csv(self, filename="nmap_scan_results.csv"):
        """Saves the scan results to a CSV file."""
        try:
            with open(filename, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(
                    ["IP Address", "Hostname", "Port", "Protocol", "Service", "State"]
                )
                for ip, (hostname, results) in self.scan_results.items():
                    for port_info in results:
                        writer.writerow(
                            [
                                ip,
                                hostname,
                                port_info["port"],
                                port_info["protocol"],
                                port_info["service"],
                                port_info["state"],
                            ]
                        )
            self.print_status(f"Scan results saved to {filename}")
        except Exception as e:
            self.print_error(f"Error saving results to CSV: {e}")

    def _get_mac_address(self, ip_address: str) -> str:
        """Gets the MAC address for a given IP address using ARP."""
        try:
            arp_request = ARP(pdst=ip_address)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            if answered_list:
                return answered_list[0][1].hwsrc
            else:
                return "N/A"
        except Exception as e:
            self.print_error(f"Error getting MAC address for {ip_address}: {e}")
            return "N/A"


if __name__ == "__main__":
    targets = input(
        "Enter target IP address(es) or CIDR range(s), separated by commas: "
    )

    scanner = CustomNmapScanner(targets)

    scanner.scan(targets)

    # Ask the user if they want to save the results to a CSV file
    save_to_csv = input("Save results to CSV file? (y/n): ")
    if save_to_csv.lower() == "y":
        csv_filename = input("Enter CSV filename (default: nmap_scan_results.csv): ")
        if not csv_filename:
            csv_filename = "nmap_scan_results.csv"
        scanner.save_results_to_csv(csv_filename)
