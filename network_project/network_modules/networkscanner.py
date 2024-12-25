#!/usr/bin/python3

import argparse
import logging
import os
import getpass
import ipaddress
import shutil
from typing import List
import netifaces
import threading
import queue
import subprocess  # For Nmap
import xml.etree.ElementTree as ET  # For XML parsing
import time  # For pausing after reset
import csv
from scapy.all import ARP, Ether, srp, conf  # For ARP scanning

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class NetworkScanner:
    MAX_THREADS = 10
    COMMON_PORTS = [
        20,
        21,
        22,
        23,
        25,
        53,
        67,
        68,
        69,
        80,
        110,
        123,
        137,
        138,
        139,
        143,
        161,
        443,
        445,
        514,
        631,
        993,
        995,
        1080,
        1194,
        1433,
        1701,
        1723,
        3306,
        3389,
        5432,
        5900,
        5901,
        8080,
        8443,
        10000,
        30778,
    ]
    SCAN_TYPES = {
        "0": "SYN",
        "1": "NULL",
        "2": "FIN",
        "3": "XMAS",
        "4": "ACK",
        "5": "Window",
        "6": "Maimon",
        "7": "UDP",
        "8": "TCP",
        "9": "IDLE",
        "10": "SCTP",
        "11": "OS",
        "12": "Script",
        "13": "BET",
        "14": "CONNECT",
    }
    DEFAULT_SCAN_TYPE = "SYN"  # OS detection

    def __init__(
        self,
        interface: str = None,  # Type hint and default value
        targets: List[str] = None,  # Type hint and default value
        ports: List[str] = None,  # Type hint and default value
        scan_type: str = DEFAULT_SCAN_TYPE,  # Type hint and default value
        nmap_path: str = "nmap",  # Type hint and default value
        threads: int = 10,  # Type hint and default value (not currently used)
        quiet: bool = False,  # Type hint and default value
        log_file: str = None,  # Type hint and default value
    ):
        self.interface = interface
        self.own_ip = self._get_ip_address()
        self.own_mac = self._get_mac_address(self.own_ip)
        self.targets = self._parse_targets(targets) if targets else []
        self.ports = self._parse_ports(ports) if ports else self.COMMON_PORTS
        self.scan_type = scan_type
        self._lock = threading.Lock()
        self.csv_filename = "network_scan_results.csv"
        self.setup_logging()

    def setup_logging(self):
        logger.setLevel(logging.INFO)

        formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s"
        )  # Define formatter once

        if self.log_file:  # Always add file handler if log_file is specified.

            file_handler = logging.FileHandler(self.log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        if not self.quiet:  # Add console handler if NOT quiet

            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)  # Use same formatter.
            logger.addHandler(console_handler)

        elif not self.log_file:  # Quiet mode, and NO log file given, add NullHandler

            logger.addHandler(logging.NullHandler())

    def _get_default_interface(self):
        """Gets the default network interface."""
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][1]  # Interface name
        except (KeyError, IndexError):  # More specific exception handling
            logger.error(
                "Could not determine default interface. Please specify -i/--interface."
            )
            return None

    def _get_ip_address(self):
        """Gets the IP address of the specified interface."""
        if self.interface:  # Check if interface is not none
            try:
                addresses = netifaces.ifaddresses(self.interface)
                return addresses[netifaces.AF_INET][0]["addr"]  # Get the IP address
            except (KeyError, IndexError):  # Handle missing key
                logger.error(
                    f"Could not get IP address for interface: {self.interface}"
                )
                return None  # Return None in case of an error
        else:
            logger.error("Interface not found, provide with -i or --interface")
            return None

    async def _get_mac_address(self, ip_address):
        if not ip_address:
            logger.error("IP not provided for MAC lookup.")  # Good error message
            return None

        try:
            conf.verb = 0

            # Explicitly specify interface for ARP scan. Use provided interface or get default interface.
            iface = self.interface or self._get_default_interface()
            if (
                not iface
            ):  # If no default interface specified, and interface is not provided, we need to log an error.
                raise OSError(
                    "No network interface specified or could not be determined."
                )

            ans, unans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
                timeout=2,
                verbose=False,
                iface=iface,  # Use specified or default interface
            )
            return ans[0][1].hwsrc if ans else None
        except OSError as e:  # Catch potential errors if interface is not correct
            if not self.quiet:
                logger.error(f"Error during ARP scan: {e}")
            return None

    def _parse_targets(self, targets_str):
        """Parses target IP addresses or networks from a list of strings."""
        targets = []
        for target_str in targets_str:
            try:
                # Attempt to parse as a single IP address
                ip = ipaddress.ip_address(target_str)
                targets.append(str(ip))
            except ValueError:
                try:
                    # Attempt to parse as a network range (CIDR)
                    network = ipaddress.ip_network(target_str, strict=False)
                    for ip in network.hosts():
                        targets.append(str(ip))
                except ValueError:
                    # Log and raise any error from network parsing
                    logger.error(
                        f"Invalid target provided: {target_str}. Skipping."
                    )  # Clear message to help the user determine which target is bad
        return targets

    def _parse_ports(self, ports_str):
        """Parses port numbers or ranges from a comma-separated string."""
        ports = []
        if ports_str:
            port_ranges = ports_str.split(",")
            for port_range in port_ranges:
                try:
                    if "-" in port_range:
                        start, end = map(int, port_range.split("-"))
                        if 0 <= start <= 65535 and 0 <= end <= 65535:
                            ports.extend(range(start, end + 1))
                        else:
                            logger.warning(f"Invalid port range: {port_range}")
                    else:
                        port = int(port_range)
                        if 0 <= port <= 65535:
                            ports.append(port)
                        else:
                            logger.warning(f"Invalid port: {port}")

                except ValueError:
                    logger.warning(f"Invalid port specification: {port_range}")

        return [str(p) for p in ports]

    def _execute_nmap_scan(self, target, ports, scan_type):
        """Executes an Nmap scan against a single target."""

        nmap_path = shutil.which("nmap")
        if nmap_path is None:
            logger.error("Nmap not found. Please install Nmap.")
            return None

        try:
            nmap_args = ["sudo", nmap_path, "-oX", "-"]

            if ports:  # Check if ports is not an empty list
                nmap_args.extend(["-p", ",".join(ports)])

            if scan_type and scan_type != "help":
                nmap_scan_type_arg = next(
                    (
                        f"-s{code.upper()}"
                        for code, name in self.SCAN_TYPES.items()  # Use items() to iterate through key-value pairs
                        if name == scan_type.upper()  # Correct scan type check
                    ),
                    None,
                )  # Find corresponding Nmap argument. Efficient and clear.

                if nmap_scan_type_arg:
                    nmap_args.append(nmap_scan_type_arg)

            nmap_args.append(
                target
            )  # Append target. Ensures target is always included in args.

            process = subprocess.run(
                nmap_args, capture_output=True, text=True, check=True
            )  # Capture errors and raise exceptions. More explicit and robust.

            return process.stdout

        except (
            subprocess.CalledProcessError
        ) as e:  # More specific error handling. Improves diagnostics.
            logger.error(f"Nmap scan failed: {e.stderr}")
            return None
        except Exception as e:
            logger.error(f"Error during Nmap execution: {e}")
            return None

    def _process_nmap_output(self, nmap_output):  # Enhanced to extract service versions
        """Processes the XML output from Nmap and extracts relevant information."""
        try:
            root = ET.fromstring(nmap_output)
            scan_results = []

            for host in root.findall("host"):
                host_info = {}
                # ... (IP, hostname, OS parsing remain the same)

                ports = []
                for port in host.find("ports").findall("port"):
                    state_element = port.find("state")
                    service_element = port.find("service")

                    port_info = {
                        "protocol": port.get("protocol"),
                        "portid": int(port.get("portid")),
                        "state": (
                            state_element.get("state")
                            if state_element is not None
                            else None
                        ),  # Handles missing "state" element
                        "service": (
                            service_element.get("name")
                            if service_element is not None
                            else None
                        ),  # Handles missing "service" element
                        "version": (
                            f"{service_element.get('product', '')} {service_element.get('version', '')}".strip()
                            if service_element is not None
                            else ""
                        ),  # Extracts and combines product and version if the "service" element exists
                    }

                    ports.append(port_info)
                host_info["ports"] = ports

                scan_results.append(host_info)

            return scan_results

        except ET.ParseError as e:
            logger.error(
                f"Error parsing Nmap XML output: {e}"
            )  # Logs XML parsing errors.
            return None

    def _parse_os_info(self, host):
        os_info = {}
        os_element = host.find("os")

        if os_element is not None:  # Corrected logic - simplified
            osmatch_element = os_element.find("osmatch")
            if osmatch_element is not None:
                os_info["osfamily"] = osmatch_element.get("name")
                os_info["osgen"] = osmatch_element.get("accuracy")

            osclass_element = os_element.find(
                "osclass"
            )  # Look for osclass, regardless of osmatch
            if osclass_element is not None:
                os_info["type"] = osclass_element.get("type")
                os_info["vendor"] = osclass_element.get("vendor")
                os_info.setdefault("osfamily", osclass_element.get("osfamily"))
                os_info.setdefault("osgen", osclass_element.get("osgen"))

        return os_info

    def _arp_scan(self, target):
        """Performs an ARP scan for a single target."""
        mac = self._get_mac_address(target)  # Use the existing _get_mac_address method
        if mac:
            return {"ip_address": target, "mac_address": mac}
        else:
            return None

    def scan(self):  # Changed from scan_targets
        """Performs both ARP and Nmap scans."""
        results = {}  # Dictionary to store combined results

        # --- ARP Scan (using threads) ---
        arp_threads = []
        arp_queue = queue.Queue()

        for target in self.targets:
            thread = threading.Thread(
                target=lambda t: arp_queue.put(self._arp_scan(t)), args=(target,)
            )
            arp_threads.append(thread)
            thread.start()

        for thread in arp_threads:
            thread.join()

        while not arp_queue.empty():
            arp_result = arp_queue.get()
            if arp_result:  # Add result to the main dictionary
                results[arp_result["ip_address"]] = arp_result

        # --- Nmap Scan ---
        if (
            self.scan_type and self.scan_type != "help"
        ):  # Added check here. More explicit and readable.
            for target in self.targets:
                nmap_output = self._execute_nmap_scan(
                    target, self.ports, self.scan_type
                )

                if nmap_output:
                    nmap_results = self._process_nmap_output(nmap_output)

                    if nmap_results:
                        for (
                            nmap_result
                        ) in nmap_results:  # Iterate through each nmap result
                            ip = nmap_result.get("ip_address")
                            if (
                                ip in results
                            ):  # Update existing results entry with nmap data
                                results[ip].update(
                                    nmap_result
                                )  # Combine/update with Nmap results
                            else:
                                results[ip] = nmap_result  # Add new entry

        return list(results.values())  # Return list of combined/updated dictionaries

    def print_results(
        self, results
    ):  # Enhanced print_results to handle service versions.
        """Prints the scan results."""
        print("-" * 70)  # Added width
        print(
            f"{'IP Address':<15} {'MAC Address':<20} {'Hostname':<25} {'OS':<20} {'Open Ports/Service':<30}"  # Updated header
        )
        print("-" * 70)  # Added width

        for result in results:
            ip_address = result.get("ip_address", "")
            mac_address = result.get("mac_address", "")
            hostname = result.get("hostname", "")
            os_info = result.get("os", {})
            os_string = (
                f"{os_info.get('osfamily', '')} {os_info.get('osgen', '')}"
                if os_info
                else ""
            )

            open_ports_services = ", ".join(
                [
                    f"{port['portid']}/{port['service']} ({port['version']})"  # Include service and version
                    for port in result.get("ports", [])
                    if port["state"] == "open"
                ]
            )

            print(
                f"{ip_address:<15} {mac_address:<20} {hostname:<25} {os_string:<20} {open_ports_services:<30}"  # Updated code
            )

    def save_results(self, results, filename="scan-results.csv"):
        """Saves the scan results to a CSV file."""
        filename = filename or self.csv_filename  # Use default if not provided

        try:
            with open(filename, "w", newline="") as csvfile:
                fieldnames = [
                    "IP Address",
                    "MAC Address",
                    "Hostname",
                    "OS Family",
                    "OS Generation",
                    "OS Vendor",
                    "Open Ports",
                ]  # All fields
                writer = csv.DictWriter(
                    csvfile, fieldnames=fieldnames, extrasaction="ignore"
                )  # Ignore extra fields
                writer.writeheader()

                for result in results:
                    os_info = result.get("os", {})  # Get OS details or an empty dict
                    ports = result.get(
                        "ports", []
                    )  # Gets the ports list or empty list.
                    open_ports_str = ", ".join(
                        [str(p["portid"]) for p in ports if p.get("state") == "open"]
                    )  # Extract open ports
                    writer.writerow(
                        {
                            "IP Address": result.get("ip_address", ""),
                            "MAC Address": result.get("mac_address", ""),
                            "Hostname": result.get("hostname", ""),
                            "OS Family": os_info.get("osfamily", ""),
                            "OS Generation": os_info.get("osgen", ""),
                            "OS Vendor": os_info.get("vendor", ""),
                            "Open Ports": open_ports_str,  # Updated code to write open ports
                        }
                    )

            logger.info(f"Scan results saved to: {filename}")

        except OSError as e:  # Handle file errors
            logger.error(f"Error saving results to file: {e}")
        except Exception as e:  # Catch other errors
            logger.error(f"Error saving CSV File: {e}")


def print_scan_types():
    print("Available Nmap Scan Types:")
    for code, scan_name in NetworkScanner.SCAN_TYPES.items():  # Changed to SCAN_TYPES
        print(f"{code}: {scan_name}")  # Print just the name, not arguments


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""A comprehensive network scanner that combines ARP scanning for fast local network discovery and Nmap scanning for detailed port and service information.
        """,
        epilog="""Examples:
          python networkscanner.py 192.168.1.1/24  # ARP and OS detection scan of network
          python networkscanner.py 192.168.1.100 -p 80,443 -s 0  # SYN scan of ports 80 and 443 on a single host
          python networkscanner.py -st  # Show available Nmap scan types
          python networkscanner.py -i eth0 192.168.5.0/24 -p 22,80,443,30778  # Scan a different network on specific ports

        For more details on scan types, run:  'python networkscanner.py -s help'
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-i", "--interface", help="Specify the network interface to use for scanning."
    )

    parser.add_argument(
        "targets",
        nargs="*",
        help="Specify target IP addresses, CIDR ranges, or hostnames (multiple targets can be space-separated).",
    )  # Updated help text for targets.

    parser.add_argument(
        "-p",
        "--ports",
        help="Specify comma-separated port numbers or ranges (e.g., 80,443,1-1024). If not provided, common ports will be scanned.",
    )

    parser.add_argument(
        "-s",
        "--scan_type",
        choices=list(NetworkScanner.SCAN_TYPES.keys()) + ["help"],
        help="Specify the Nmap scan type. For available types, run with '-st' or '-s help'. Defaults to OS detection.",
        default=NetworkScanner.DEFAULT_SCAN_TYPE,
    )  # Updated help text for scan_type

    parser.add_argument(
        "-st",
        "--show_scan_types",
        action="store_true",
        help="Display available Nmap scan types and exit.",
    )

    args = parser.parse_args()

    if (
        args.scan_type == "help"
    ):  # Show help for scan types. This implements the special handling requested.
        print_scan_types()
        exit()

    if args.show_scan_types:
        print_scan_types()
        exit()

    if not args.targets:
        parser.print_help()  # Print help if no targets provided
        exit()

    try:
        scanner = NetworkScanner(
            args.interface, args.targets, args.ports, args.scan_type
        )  # Added error handling for scanner init
        scan_results = scanner.scan()

        if scan_results:
            scanner.print_results(scan_results)
            scanner.save_results(
                scan_results
            )  # Save to CSV (using default or specified filename)
        else:
            logger.warning("No scan results found.")

    except KeyboardInterrupt:
        print("\nScan interrupted.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")

    # Test calls (You can expand these for more complete tests later):
    print(f"Default Interface: {scanner.interface}")
    print(f"Own IP: {scanner.own_ip}")
    print(f"Own MAC: {scanner.own_mac}")
    print("Targets:", scanner.targets)
    print("Ports:", scanner.ports)
