#!/usr/bin/python3

import subprocess
import threading
import ipaddress
import argparse

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
        command = ["nmap", "-v", "-oX", "-"]

        # ... (debug print statements - you can remove these later)

        # Reset self.arguments if ports are specified
        if self.ports:
            self.arguments = ""  # Clear default arguments if ports are provided
            command.extend(["-p", self.ports])
        elif self.arguments:  # Only add default arguments if not specifying ports
            command.extend(self.arguments.split())

        # Add
        stmt = f"\n\n\t\tAdding target\n\t\t{target}\n"
        print(stmt)
        command.append(target)

        print(f"\n\n\t\tFull Nmap Command: {command}\n\n")

        try:
            nmap_process = subprocess.run(
                command,
                capture_output=True,
                shell=False,
                timeout=180,
                cwd="/home/rick/private/projects/desktop/bash/scratch/network_project/refs",
                text=True,
            )

            # print(f"\n\n\tnamp_process.stderr: {nmap_process.stderr}\n\n")
            # print(f"\tnmap_process.stdout: {nmap_process.stdout}")

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
                        hostname_element = host.find("hostnames/hostname")
                        hostname = (
                            hostname_element.get("name")
                            if hostname_element is not None
                            else "N/A"
                        )

                        port_info = []
                        ports = host.find("ports")
                        if ports is not None:
                            for port_elem in ports.findall(
                                "*"
                            ):  # Iterate over all children of <ports>
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
                                    port_info.append(
                                        {
                                            "port": f"N/A ({count} ports)",
                                            "protocol": "tcp",  # Assuming TCP for extraports
                                            "state": state,
                                            "service": "Unknown",
                                        }
                                    )
                        return hostname, port_info
            return None, []  # Host not found

        except ET.ParseError as e:
            self.print_error(f"Error parsing Nmap output for {target}: {e}")
            return None, []

    def print_results(self) -> None:
        """Prints the scan results to the console in a structured format."""
        for ip, (hostname, results) in self.scan_results.items():
            print(f"{TextColors.HEADER}Host: {hostname} ({ip}){TextColors.ENDC}")

            if results:
                print(f"{TextColors.OKBLUE}  Port\t\tState\t\tService{TextColors.ENDC}")
                for port_info in results:
                    state_color = (
                        TextColors.OKGREEN
                        if port_info["state"] == "open"
                        else (
                            TextColors.WARNING
                            if port_info["state"] == "filtered"
                            else TextColors.FAIL
                        )
                    )
                    port = port_info["port"]
                    state = port_info["state"].upper()
                    service = port_info["service"]
                    print(
                        f"  {port:<10}  {state_color}{state:<10}{TextColors.ENDC}  {service}"
                    )
            else:
                print(f"  {TextColors.WARNING}No open ports found.{TextColors.ENDC}")
            print("-" * 40)

    def scan(self, targets: str):
        """Scans the specified targets and stores the results."""
        targets = self._parse_targets(targets)
        threads = []
        self.xml_outputs = []  # Store XML outputs here

        for target in targets:
            thread = threading.Thread(target=self._scan_target, args=(target,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # Process XML outputs after all threads finish
        for target, xml_output in self.xml_outputs:
            if xml_output:
                hostname, open_ports = self._parse_nmap_output(xml_output, target)
                self.scan_results[target] = (hostname, open_ports)

        self.print_results()  # Print results after all threads finish

    def _scan_target(self, target):
        xml_output = self._execute_nmap_scan(target)
        if xml_output:
            # print(f"XML Output for {target}:\n{xml_output}")
            hostname, open_ports = self._parse_nmap_output(
                xml_output, target
            )  # Correctly unpack the tuple
            self.scan_results[target] = (hostname, open_ports)

            # Append to xml_outputs if needed
            self.xml_outputs.append((target, xml_output))

            # self.xml_outputs.append((target, xml_output))
            return xml_output

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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Custom Nmap Port Scanner")
    parser.add_argument(
        "targets",
        nargs="*",  # Allow zero or more targets
        help="Target IP address(es) or CIDR range(s), separated by commas",
    )
    parser.add_argument(
        "-p",
        "--ports",
        help="Port(s) to scan (e.g., 80,443,1000-1500). Default: common ports",
    )
    args = parser.parse_args()

    # Determine targets from arguments or prompt if none provided
    if args.targets:
        targets = ",".join(args.targets)  # Combine targets into a string
    else:
        targets = input(
            "Enter target IP address(es) or CIDR range(s), separated by commas: "
        )

    scanner = CustomNmapScanner(targets, ports=args.ports)
    scanner.scan(targets)

""" if __name__ == "__main__":
    targets = input(
        "Enter target IP address(es) or CIDR range(s), separated by commas: "
    )

    scanner = CustomNmapScanner(targets)

    scanner.scan(targets)

    # --- Test _parse_ports ---
    test_scanner = CustomNmapScanner("127.0.0.1")  # Create a temporary scanner object
    test_ports = [
        "80,443,1000-1010",  # Valid
        "22, 80, 443",  # Valid with spaces
        "80-82,443",  # Valid range
        "80",  # Valid single port
        "1-65535",  # Valid full range
        "80,443,badport",  # Invalid
        "1000-999",  # Invalid range
        "0,80",  # Invalid port number
        "65536,80",  # Invalid port number
        "80,",  # Trailing comma
        ",80",  # Leading comma
        "80,  ,443",  # Extra comma
        "",  # Empty string
    ]
    for port_str in test_ports:
        print(f"Testing ports: '{port_str}'")
        try:
            parsed_ports = test_scanner._parse_ports(port_str)
            print(f"  Parsed ports: {parsed_ports}")
        except Exception as e:
            print(f"  Error: {e}") """
