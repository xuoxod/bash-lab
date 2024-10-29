#!/usr/bin/python3

import nmap
import logging
from typing import Dict, List, Union, Tuple
from network_modules.helpers.utils import Utils  # Import the Utils class

logging.basicConfig(level=logging.INFO)


class NmapPortScanner:
    def __init__(self, arguments="-T4 -F"):
        """Initializes the NmapPortScanner with optional nmap arguments."""
        self.nm = nmap.PortScanner()
        self.arguments = arguments

    def scan_network(
        self, target: str, ports: str = None
    ) -> Tuple[Dict[str, List[int]], List[str]]:
        """Scans a network range or a single IP for open ports using nmap.

        Args:
            target: The target IP address or CIDR range to scan.
            ports: A comma-separated string of ports to scan (e.g., "21-25,80,443").
                   If None, default Nmap behavior is used.

        Returns:
            A tuple containing:
                - A dictionary where keys are IP addresses and values are lists of open ports.
                - A list of error messages encountered during port parsing.
        """
        errors = []  # Store error messages
        try:
            logging.info(f"Scanning target: {target}...")

            if ports:
                # Parse the ports string into a list of integers and strings
                ports_list = [int(p) if p.isdigit() else p for p in ports.split(",")]
                # Convert port ranges to a comma-separated string of individual ports
                port_string, parse_errors = self._expand_port_ranges(ports_list)
                errors.extend(parse_errors)  # Add port parsing errors

                if errors:  # Print errors if any occurred during parsing
                    for error in errors:
                        print(
                            f"{Utils.TextColors.FAIL}Error: {error}{Utils.TextColors.ENDC}"
                        )

                self.nm.scan(hosts=target, arguments=self.arguments, ports=port_string)
            else:
                self.nm.scan(hosts=target, arguments=self.arguments)

            results = {}

            for ip in self.nm.all_hosts():
                results[ip] = []
                for port in self.nm[ip]["tcp"].keys():  # Iterate through ports in 'tcp'
                    if self.nm[ip].has_tcp(port):  # Now 'port' is defined
                        if self.nm[ip]["tcp"][port]["state"] == "open":
                            results[ip].append(port)

        except nmap.PortScannerError as e:
            logging.error(f"Nmap scan failed: {e}")
            return {}, [str(e)]  # Return an empty dictionary and the error message
        return results, errors

    def _expand_port_ranges(
        self, ports: List[Union[int, str]]
    ) -> Tuple[str, List[str]]:
        """Expands port ranges in the ports list into individual port numbers."""
        expanded_ports = []
        errors = []  # Collect error messages
        for port in ports:
            if isinstance(port, str) and "-" in port:
                try:
                    start, end = map(int, port.split("-"))
                    if 1 <= start <= end <= 65535:
                        expanded_ports.extend(range(start, end + 1))
                    else:
                        errors.append(
                            f"Invalid port range: {port}. Port ranges must be between 1 and 65535."
                        )
                except ValueError:
                    errors.append(
                        f"Invalid port range format: {port}. Correct format: 'start-end' (e.g., '21-25')."
                    )
            elif isinstance(port, int):
                if 1 <= port <= 65535:
                    expanded_ports.append(port)
                else:
                    errors.append(
                        f"Invalid port number: {port}. Port numbers must be between 1 and 65535."
                    )
            else:
                errors.append(
                    f"Invalid port format: {port}. Ports must be integers or ranges (e.g., '80' or '21-25')."
                )
        return ",".join(map(str, expanded_ports)), errors  # Return ports and errors

    def print_results(self, results: Dict[str, List[int]]) -> None:
        """Prints the scan results to the console."""
        for target, result in results.items():
            print(
                f"{Utils.TextColors.OKGREEN}\n----- Results for {target} -----{Utils.TextColors.ENDC}"
            )

            # --- Print Open Ports ---
            if result:
                print(
                    f"  {Utils.TextColors.OKBLUE}Open Ports:{Utils.TextColors.ENDC} {', '.join(map(str, result))}"
                )
            else:
                print(
                    f"  {Utils.TextColors.WARNING}No open ports found.{Utils.TextColors.ENDC}"
                )

            # --- Print OS Detection (if available) ---
            if "osmatch" in self.nm[target] and self.nm[target]["osmatch"]:
                os_guesses = self.nm[target]["osmatch"]
                best_guess = max(os_guesses, key=lambda x: int(x["accuracy"]))
                print(
                    f"\n  {Utils.TextColors.OKCYAN}OS Detection:{Utils.TextColors.ENDC}"
                )
                print(
                    f"    {Utils.TextColors.OKCYAN}Most Likely OS:{Utils.TextColors.ENDC} {best_guess['name']} ({best_guess['accuracy']}% accuracy)"
                )
            else:
                print(
                    f"  {Utils.TextColors.WARNING}Could not determine the OS.{Utils.TextColors.ENDC}"
                )
