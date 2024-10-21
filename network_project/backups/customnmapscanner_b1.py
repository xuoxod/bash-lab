import subprocess
import threading
import time
import ipaddress
import re
from typing import List, Dict, Tuple


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
    def __init__(self, target: str, ports: str = None, arguments: str = None):
        self.target = target
        self.ports = self._parse_ports(ports) if ports else None
        self.arguments = arguments if arguments else "-T4 -F"
        self.scan_results = {}
        self.stop_event = threading.Event()

    def _parse_ports(self, ports_string: str) -> str:
        """Parses a string of ports and port ranges into a comma-separated string for nmap."""
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

    def _execute_nmap_scan(self, ip: str) -> None:
        """Executes an nmap scan on a single IP address."""
        try:
            command = ["nmap", self.arguments, "-oX", "-", ip]
            if self.ports:
                command.extend(["-p", self.ports])
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            if process.returncode == 0:
                self.scan_results[ip] = self._parse_nmap_output(output.decode())
            else:
                self.print_error(f"Nmap scan failed for {ip}: {error.decode().strip()}")
        except Exception as e:
            self.print_error(f"Error during nmap scan for {ip}: {e}")

    def _parse_nmap_output(self, nmap_output: str) -> Dict:
        """Parses the XML output from nmap and returns a dictionary of open ports."""
        # TODO: Implement robust parsing of nmap's XML output
        # For now, just return a placeholder
        return {"open_ports": []}

    def scan(self) -> None:
        """Scans the target network or IP address."""
        try:
            self.print_status(
                f"Starting scan on target: {self.target} with arguments: {self.arguments}"
            )
            if self.ports:
                self.print_status(f"Scanning ports: {self.ports}")

            # Validate and handle target (single IP or network)
            try:
                ipaddress.ip_address(self.target)
                targets = [self.target]  # Single IP
            except ValueError:
                try:
                    targets = [
                        str(ip) for ip in ipaddress.ip_network(self.target).hosts()
                    ]
                except ValueError as e:
                    self.print_error(f"Invalid target: {e}")
                    return

            threads = []
            for ip in targets:
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
            self.stop_event.set()
        except Exception as e:
            self.print_error(f"An error occurred during the scan: {e}")

    def print_results(self) -> None:
        """Prints the scan results to the console."""
        # TODO: Implement colorful and formatted output
        for ip, results in self.scan_results.items():
            print(f"Results for {ip}:")
            print(results)

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
    scanner = CustomNmapScanner(target="127.0.0.1", ports="80,443,8080")
    scanner.scan()
