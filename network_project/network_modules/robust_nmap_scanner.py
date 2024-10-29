# network_modules/robust_nmap_scanner.py

import nmap
import logging
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from network_modules.helpers.colors import TextColors
from network_modules.helpers.utils import Utils

logging.basicConfig(level=logging.DEBUG)

# Define common ports and scan types as constants
COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    135,
    139,
    443,
    445,
    1433,
    1434,
    3306,
    3389,
    5432,
    5900,
    5985,
    5986,
    8080,
    8443,
    9000,
    9090,
    9200,
    9418,
]

SCAN_TYPES = {
    "SYN Scan (Stealth)": "-sS",
    "TCP Connect Scan": "-sT",
    "UDP Scan": "-sU",
    "FIN Scan (Stealth)": "-sF",
    "NULL Scan (Stealth)": "-sN",
    "Xmas Scan (Stealth)": "-sX",
    "ACK Scan (Firewall Detection)": "-sA",
    "Window Scan (Firewall Detection)": "-sW",
    "Maimon Scan (Firewall Detection)": "-sM",
    "Ping Scan (Host Discovery)": "-sP",
    "OS Detection": "-O",
    "Aggressive Scan": "-A",
    "Vulnerability Scan": "-sV --script vuln",
    "Service Version Detection": "-sV",
    "TCP ACK Scan": "-sA",
    "TCP Window Scan": "-sW",
    "TCP Maimon Scan": "-sM",
    "UDP Scan (Top 100 Ports)": "-sU -F",
    "Comprehensive Scan (Intense)": "-T4 -A -v",
    "Fast Scan": "-T4 -F",
    "Sneaky Scan": "-T2 -sS -f",
    "Paranoid Scan": "-T1 -sS -f",
    "Intense Scan, All TCP Ports": "-p- -T4 -A -v",
    "Intense Scan, No Ping": "-Pn -T4 -A -v",
    "Firewall Bypass Scan": "-f -sS -T4 -A -v",
}

DEFAULT_SCAN_TYPE = "OS Detection"  # Default scan type


class RobustNmapScanner:
    def __init__(
        self,
        targets: str = None,
        ports: str = None,
        scan_type: str = DEFAULT_SCAN_TYPE,
        max_threads: int = 20,  # Adjust as needed
    ):
        """Initializes the RobustNmapScanner with target, ports, and scan type."""
        self.nm = nmap.PortScanner()
        self.targets = targets
        self.ports = self._parse_ports(ports) if ports else COMMON_PORTS
        self.scan_type = scan_type
        self.arguments = SCAN_TYPES.get(self.scan_type, SCAN_TYPES[DEFAULT_SCAN_TYPE])
        self.max_threads = max_threads
        self.scan_results = {}

        # Run the scan automatically if no custom information is provided
        if not targets:
            self.targets = self._get_default_target()
        self.scan()

    def _get_default_target(self) -> str:
        """Gets the default target (current network) if no target is provided."""
        try:
            return Utils.get_local_ip() + "/24"
        except Exception as e:
            self.print_error(f"Error getting default target: {e}")
            return "127.0.0.1"  # Fallback to localhost

    def _parse_ports(self, ports_str: str) -> List[int]:
        """Parses a string of ports into a list of integers."""
        ports = []
        for port_str in ports_str.split(","):
            if "-" in port_str:
                try:
                    start, end = map(int, port_str.split("-"))
                    ports.extend(range(start, end + 1))
                except ValueError:
                    self.print_error(f"Invalid port range: {port_str}")
            else:
                try:
                    port = int(port_str)
                    ports.append(port)
                except ValueError:
                    self.print_error(f"Invalid port number: {port_str}")
        return ports

    def _scan_target(self, target: str) -> Dict:
        """Scans a single target using nmap."""
        try:
            self.print_status(f"Scanning target: {target}...")
            self.nm.scan(
                hosts=target, arguments=self.arguments, ports=self._ports_to_string()
            )
            return self.nm[target]
        except nmap.PortScannerError as e:
            self.print_error(f"Nmap scan failed for {target}: {e}")
            return {}

    def _ports_to_string(self) -> str:
        """Converts the list of ports to a comma-separated string for nmap."""
        return ",".join(str(port) for port in self.ports)

    def scan(self) -> None:
        """Scans the targets concurrently and stores the results."""
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._scan_target, target): target
                for target in self.targets.split(",")
            }
            for future in as_completed(futures):
                target = futures[future]
                self.scan_results[target] = future.result()

    def print_results(self) -> None:
        """Prints the scan results to the console with pretty printing."""
        for target, result in self.scan_results.items():
            print(
                f"{TextColors.OKGREEN}\n----- Results for {target} -----{TextColors.ENDC}"
            )
            if "tcp" in result:
                for port, data in result["tcp"].items():
                    if data["state"] == "open":
                        print(
                            f"  {TextColors.OKBLUE}Port {port}/{data['name']} is open{TextColors.ENDC} - {TextColors.WARNING}{data['product']} {data['version']}{TextColors.ENDC}"
                        )
            else:
                print(
                    f"  {TextColors.WARNING}No open TCP ports found.{TextColors.ENDC}"
                )

            if "osmatch" in result and result["osmatch"]:
                print(f"\n  {TextColors.OKCYAN}OS Detection:{TextColors.ENDC}")
                for osmatch in result["osmatch"]:
                    print(
                        f"    {TextColors.OKCYAN}Name:{TextColors.ENDC} {osmatch['name']}, {TextColors.OKCYAN}Accuracy:{TextColors.ENDC} {osmatch['accuracy']}%"
                    )
            else:
                print(f"  {TextColors.WARNING}OS detection failed.{TextColors.ENDC}")

    def print_status(self, message: str) -> None:
        """Prints a status message to the console."""
        print(f"{TextColors.OKBLUE}[*] {message}{TextColors.ENDC}")

    def print_error(self, message: str) -> None:
        """Prints an error message to the console."""
        print(f"{TextColors.FAIL}[!] {message}{TextColors.ENDC}")


if __name__ == "__main__":
    scanner = RobustNmapScanner()
    scanner.print_results()
