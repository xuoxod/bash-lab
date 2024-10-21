import subprocess
import threading
import ipaddress
import re
from typing import List, Dict, Tuple
from xml.etree import ElementTree as ET


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
    # Predefined Nmap Scan Types
    SCAN_TYPES = {
        "1": {"name": "Intense Scan", "arguments": "-T4 -A -v"},
        "2": {"name": "Intense Scan plus UDP", "arguments": "-sS -sU -T4 -A -v"},
        "3": {
            "name": "Intense Scan, all TCP ports",
            "arguments": "-p 1-65535 -T4 -A -v",
        },
        "4": {"name": "Intense Scan, no ping", "arguments": "-T4 -A -v -Pn"},
        "5": {"name": "Ping Scan", "arguments": "-sn"},
        "6": {"name": "Quick Scan", "arguments": "-T4 -F"},
        "7": {"name": "Quick Scan plus", "arguments": "-sV -T4 -O -F --version-light"},
        "8": {"name": "Quick traceroute", "arguments": "-sn --traceroute"},
        "9": {"name": "Regular Scan", "arguments": "-T4 -v"},
        "10": {
            "name": "Slow comprehensive scan",
            "arguments": "-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 -sC 'default or (discovery and safe)'",
        },
        "11": {"name": "TCP SYN Scan", "arguments": "-sS"},
        "12": {"name": "TCP Connect Scan", "arguments": "-sT"},
        "13": {"name": "TCP ACK Scan", "arguments": "-sA"},
        "14": {"name": "TCP Window Scan", "arguments": "-sW"},
        "15": {"name": "TCP Maimon Scan", "arguments": "-sM"},
        "16": {"name": "UDP Scan", "arguments": "-sU"},
        "17": {"name": "TCP Null Scan", "arguments": "-sN"},
        "18": {"name": "TCP FIN Scan", "arguments": "-sF"},
        "19": {"name": "TCP Xmas Scan", "arguments": "-sX"},
        "20": {"name": "SCTP INIT Scan", "arguments": "-sY"},
    }

    # Common Ports
    COMMON_PORTS = {
        "1": {"name": "HTTP", "ports": "80"},
        "2": {"name": "HTTPS", "ports": "443"},
        "3": {"name": "SSH", "ports": "22"},
        "4": {"name": "FTP", "ports": "21"},
        "5": {"name": "Telnet", "ports": "23"},
        "6": {"name": "SMTP", "ports": "25"},
        "7": {"name": "DNS", "ports": "53"},
        "8": {"name": "DHCP", "ports": "67-68"},
        "9": {"name": "TFTP", "ports": "69"},
        "10": {"name": "SNMP", "ports": "161-162"},
        "11": {"name": "RDP", "ports": "3389"},
        "12": {"name": "MySQL", "ports": "3306"},
        "13": {"name": "PostgreSQL", "ports": "5432"},
        "14": {"name": "MongoDB", "ports": "27017"},
        "15": {"name": "Redis", "ports": "6379"},
        "16": {"name": "VNC", "ports": "5900-5903"},
        "17": {"name": "SMB", "ports": "445"},
        "18": {"name": "LDAP", "ports": "389"},
        "19": {"name": "IMAP", "ports": "143"},
        "20": {"name": "POP3", "ports": "110"},
    }

    def __init__(self, targets: str, ports: str = None, scan_type: str = None):
        self.targets = self._parse_targets(targets)
        self.ports = self._parse_ports(ports) if ports else None
        self.arguments = self._get_scan_arguments(scan_type)
        self.scan_results = {}
        self.stop_event = threading.Event()

    def _parse_targets(self, targets_string: str) -> List[str]:
        """Parses a string of targets (IPs, CIDRs, ranges) into a list of IP addresses."""
        targets = []
        for target in targets_string.split(","):
            try:
                ipaddress.ip_address(target)
                targets.append(target)  # Single IP
            except ValueError:
                try:
                    targets.extend(
                        [str(ip) for ip in ipaddress.ip_network(target).hosts()]
                    )
                except ValueError as e:
                    self.print_error(f"Invalid target: {e}")
        return targets

    def _parse_ports(self, ports_string: str) -> str:
        """Parses a string of ports and port ranges into a comma-separated string for nmap."""
        if not ports_string:  # Handle the case where ports_string is empty
            return None
        try:
            port_ranges = re.findall(r"(\d+-\d+|\d+)", ports_string)
            expanded_ports = []
            for port_range in port_ranges:
                if "-" in port_range:
                    start, end = map(int, port_range.split("-"))
                    expanded_ports.extend(range(start, end + 1))
                else:
                    expanded_ports.append(int(port_range))
            return ",".join(str(port) for port in expanded_ports)
        except Exception as e:
            self.print_error(f"Error parsing ports: {e}")
            return ""

    def _get_scan_arguments(self, scan_type: str) -> str:
        """Gets the nmap arguments based on the selected scan type."""
        if scan_type and scan_type in self.SCAN_TYPES:
            return self.SCAN_TYPES[scan_type]["arguments"]
        else:
            return "-T4 -F"  # Default scan

    def _execute_nmap_scan(self, ip: str) -> None:
        """Executes an nmap scan on a single IP address."""
        try:
            command = ["nmap", "-oX", "-", ip]  # Start with basic command

            # Add port specification
            if self.ports:
                if self.ports == "1-65535":  # Check if scanning all ports
                    command.append("-p-")
                else:
                    command.extend(["-p", self.ports])

            command.extend(self.arguments.split())  # Add other arguments

            subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )  # Run the command directly
        except Exception as e:
            self.print_error(f"Error during nmap scan for {ip}: {e}")

    def _parse_nmap_output(self, nmap_output: str) -> Dict:
        """Parses the XML output from nmap and returns a dictionary of open ports."""
        results = {}
        try:
            root = ET.fromstring(nmap_output)
            for host in root.findall("host"):
                address = host.find("address").get("addr")
                results[address] = {"ports": []}  # Always initialize 'ports'
                for port in host.find("ports").findall("port"):
                    if port.find("state").get("state") == "open":
                        port_data = {
                            "port": port.get("portid"),
                            "protocol": port.get("protocol"),
                            "service": port.find("service").get("name", "Unknown"),
                        }
                        results[address]["ports"].append(port_data)
        except ET.ParseError as e:
            self.print_error(f"Error parsing nmap XML output: {e}")
        return results

    def print_results(self) -> None:
        """Prints the scan results to the console."""
        for ip, results in self.scan_results.items():
            print(f"{TextColors.OKGREEN}Results for {ip}:{TextColors.ENDC}")
            if results.get(
                "ports"
            ):  # Use get() to avoid KeyError if 'ports' is missing
                for port_info in results["ports"]:
                    print(
                        f"  {TextColors.OKBLUE}Port {port_info['port']}/{port_info['protocol']} is open{TextColors.ENDC} - {TextColors.WARNING}{port_info['service']}{TextColors.ENDC}"
                    )
            else:
                print(f"  {TextColors.WARNING}No open ports found.{TextColors.ENDC}")

    def scan(self) -> None:
        """Scans the target network or IP address."""
        try:
            self.print_status(
                f"Starting scan on targets: {', '.join(self.targets)} with arguments: {self.arguments}"
            )
            if self.ports:
                self.print_status(f"Scanning ports: {self.ports}")

            threads = []
            for ip in self.targets:
                if self.stop_event.is_set():
                    break  # Stop scanning if stop_event is set
                thread = threading.Thread(target=self._execute_nmap_scan, args=(ip,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            self.print_results()
        except KeyboardInterrupt:
            self.print_warning("\nScan interrupted by user.")
            self.stop_event.set()  # Signal threads to stop
            # Wait for threads to finish (optional, but good practice)
            for thread in threads:
                thread.join()
        except Exception as e:
            self.print_error(f"An error occurred during the scan: {e}")

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
