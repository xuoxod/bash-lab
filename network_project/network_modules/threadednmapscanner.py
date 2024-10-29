#!/usr/bin/python3

import subprocess
import threading
import ipaddress
import queue
from typing import List, Dict, Tuple
import xml.etree.ElementTree as ET
import argparse
import csv
from datetime import datetime

# Import Scapy (make sure it's installed: pip install scapy)
from scapy.all import ARP, Ether, srp


# ... (TextColors class remains the same)
class TextColors:
    # ANSI escape codes for text coloring
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


class ThreadedNmapScanner:
    MAX_THREADS = 10  # Start with a lower number, adjust as needed
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
        "1": {"name": "SYN Scan (Stealth)", "arguments": "-sS"},
        "2": {"name": "TCP Connect Scan", "arguments": "-sT"},
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
        "13": {"name": "Vulnerability Scan", "arguments": "-sV --script vuln"},
        "14": {"name": "Service Version Detection", "arguments": "-sV"},
        # ... Add more scan types here ...
    }

    DEFAULT_SCAN_TYPE = "11"  # Default to OS Detection

    def __init__(
        self,
        targets: str = None,
        ports: str = None,
        scan_type: str = DEFAULT_SCAN_TYPE,
    ):
        self._targets = self._parse_targets(targets) if targets else []
        self._ports = self._parse_ports(ports) if ports else []
        if not ports:
            self.add_common_ports()
        self.scan_type = scan_type
        self.csv_filename = "tns_scan_results.csv"  # Default CSV filename
        self.scan_results: Dict[str, Tuple[str, List[Dict]]] = {}
        self.work_queue = queue.Queue()
        self.output_queue = queue.Queue()
        self.stop_event = threading.Event()

    # ... (Getters and setters for targets, ports remain the same)
    @property
    def ports(self):
        return self._ports

    @ports.setter
    def ports(self, ports_input: str):
        self._ports = self._parse_ports(ports_input)

    def add_ports(self, ports_input: str):
        """Adds ports to the existing list of ports to scan."""
        # self._ports.extend(self._parse_ports(ports_input))
        self._ports = self._parse_ports(ports_input)

    def add_common_ports(self):
        """Adds the common ports to the list of ports to scan, avoiding duplicates."""
        for port in self.COMMON_PORTS:
            if str(port) not in self._ports:
                self._ports.append(str(port))

    def _parse_targets(self, target_input: str) -> List[str]:
        """Parses target input, handling single IPs, ranges, and CIDR."""
        targets = []
        for target in target_input.split(","):
            target = target.strip()
            try:
                ipaddress.ip_address(target)  # Single IP
                targets.append(target)
            except ValueError:
                try:
                    network = ipaddress.ip_network(target)  # CIDR range
                    targets.extend([str(ip) for ip in network])
                except ValueError:
                    try:
                        # IP range (e.g., 192.168.1.1-192.168.1.10)
                        start, end = target.split("-")
                        start_octets = list(map(int, start.split(".")))
                        end_octets = list(map(int, end.split(".")))
                        if len(start_octets) == 4 and len(end_octets) == 4:
                            for i in range(start_octets[-1], end_octets[-1] + 1):
                                targets.append(
                                    f"{start_octets[0]}.{start_octets[1]}.{start_octets[2]}.{i}"
                                )
                        else:
                            self.print_error(f"Invalid IP range format: {target}")
                    except Exception as e:
                        self.print_error(f"Invalid target format: {target}. Error: {e}")
        return targets

    def _parse_ports(self, ports_input: str) -> List[str]:
        """Parses port input, handling single ports and ranges."""
        ports = []
        for port_str in ports_input.split(","):
            port_str = port_str.strip()
            if "-" in port_str:
                try:
                    start, end = map(int, port_str.split("-"))
                    if 1 <= start <= end <= 65535:
                        ports.extend([str(p) for p in range(start, end + 1)])
                    else:
                        self.print_error(f"Invalid port range: {port_str}")
                except ValueError:
                    self.print_error(f"Invalid port range format: {port_str}")
            else:
                try:
                    port = int(port_str)
                    if 1 <= port <= 65535:
                        ports.append(str(port))
                    else:
                        self.print_error(f"Invalid port number: {port}")
                except ValueError:
                    self.print_error(f"Invalid port format: {port_str}")
        return ports

    def _execute_nmap_scan(self, target: str) -> str:  # Returns XML output
        print("DEBUG: Ports before Nmap command:", self._ports)

        """Executes the Nmap scan on a single target."""
        command = [
            "nmap",
            "-v",
            "-oX",
            "-",  # Output XML to stdout
            self.SCAN_TYPES[self.scan_type][
                "arguments"
            ],  # Use selected scan type arguments
            "-p",
            ",".join(self._ports),
            target,
        ]

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=180,
            )

            if process.stderr:
                self.print_error(f"Nmap error for {target}: {process.stderr}")
                return ""  # Return empty string on error
            return process.stdout  # Return XML output
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            self.print_error(f"Error scanning {target}: {e}")
            return ""  # Return empty string on error

    def _worker_thread(self):
        """Worker thread function to process targets from the queue."""
        while not self.stop_event.is_set():
            try:
                target = self.work_queue.get(timeout=1)
                self.output_queue.put((None, f"Scanning target: {target} ..."))
                xml_output = self._execute_nmap_scan(target)
                self.output_queue.put((target, xml_output))
                self.work_queue.task_done()
            except queue.Empty:
                pass

    def _output_thread(self):
        """Output thread function to process results and print output."""
        while not self.stop_event.is_set():
            try:
                target, output = self.output_queue.get(timeout=1)
                if target is None:  # Status message
                    self.print_status(output)
                else:
                    if output:  # Only process if there's XML output
                        hostname, open_ports = self._process_nmap_output(target, output)
                        self.scan_results[target] = (hostname, open_ports)
                        self.print_results(target)
                self.output_queue.task_done()
            except queue.Empty:
                pass

    def _process_nmap_output(
        self, target: str, xml_output: str
    ) -> Tuple[str, List[Dict]]:
        """Parses the XML output from Nmap."""
        try:
            root = ET.fromstring(xml_output)
            hostname = "N/A"
            open_ports = []

            for host in root.findall("host"):
                # Extract hostname
                hostnames = host.findall("hostnames/hostname")
                if hostnames:
                    hostname = hostnames[0].get("name", "N/A")

                # Extract open ports
                for port in host.findall("ports/port"):
                    if port.find("state").get("state") == "open":
                        port_info = {
                            "port": port.get("portid"),
                            "protocol": port.get("protocol"),
                            "service": port.find("service").get("name", "N/A"),
                            "state": port.find("state").get("state"),
                        }
                        open_ports.append(port_info)

            return hostname, open_ports

        except ET.ParseError as e:
            self.print_error(f"Error parsing Nmap output: {e}")
            return "N/A", []

    def print_results(self, target: str = None) -> None:
        """Prints the scan results in a colorful and organized format."""
        if target:
            hostname, results = self.scan_results.get(target, ("N/A", []))
            print(f"{TextColors.HEADER}Host: {hostname} ({target}){TextColors.ENDC}")

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

    def print_status(self, message: str) -> None:
        print(f"{TextColors.OKBLUE}[*] {message}{TextColors.ENDC}")

    def print_error(self, message: str) -> None:
        print(f"{TextColors.FAIL}[!] {message}{TextColors.ENDC}")

    def print_warning(self, message: str) -> None:
        print(f"{TextColors.WARNING}[!] {message}{TextColors.ENDC}")

    def scan(self) -> None:
        """Starts the threaded scan."""
        self.stop_event.clear()  # Reset the stop event
        for target in self._targets:
            self.work_queue.put(target)

        # Create and start worker threads
        threads = []
        for _ in range(min(self.MAX_THREADS, len(self._targets))):
            thread = threading.Thread(target=self._worker_thread)
            thread.daemon = (
                True  # Allow main thread to exit even if workers are running
            )
            threads.append(thread)
            thread.start()

        # Start the output thread
        output_thread = threading.Thread(target=self._output_thread)
        output_thread.daemon = True
        output_thread.start()

        # Wait for all tasks to be completed
        self.work_queue.join()
        self.output_queue.join()

        # Ask user if they want to save results to CSV
        # save_to_csv = input("Save results to CSV file? (y/n): ")

        # if save_to_csv.lower() == "y":
        #     self.save_results_to_csv()

        # ... (Optionally wait for threads to finish: threads.join(), output_thread.join())

    def stop(self):
        """Stops the scan."""
        self.print_warning("Stopping the scanner...")
        self.stop_event.set()

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

    def save_results_to_csv(self):
        """Saves the scan results to a CSV file, prompting for filename if desired."""
        save_to_default = input(f"Save to default file ({self.csv_filename})? (y/n): ")
        if save_to_default.lower() != "y":
            self.csv_filename = input("Enter CSV filename: ")

        try:
            with open(self.csv_filename, "a", newline="") as csvfile:
                writer = csv.writer(csvfile)

                # Write header only if file is empty
                if csvfile.tell() == 0:
                    writer.writerow(
                        [
                            "Node IP",
                            "MAC Address",
                            "Hostname",
                            "Open Port",
                            "Protocol",
                            "Service",
                            "State",
                        ]
                    )

                for target, (hostname, open_ports) in self.scan_results.items():
                    mac_address = self._get_mac_address(target)
                    for port_info in open_ports:
                        writer.writerow(
                            [
                                target,
                                mac_address,
                                hostname,
                                port_info["port"],
                                port_info["protocol"],
                                port_info["service"],
                                port_info["state"],
                            ]
                        )

            self.print_status(f"Scan results saved to {self.csv_filename}")
        except Exception as e:
            self.print_error(f"Error saving results to CSV: {e}")

    def run_scan(self):
        """Starts the threaded scan and returns the results."""
        self.scan()  # Use the existing scan method
        return self.scan_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Threaded Nmap Port Scanner",
        epilog="Example: python3 threadednmapscanner.py -t 192.168.1.1,192.168.1.10-192.168.1.20,192.168.1.0/24 -p 80,443,8080 -s 12",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-t",
        "--targets",
        required=True,
        help="Comma-separated list of targets (IPs, ranges, CIDR)",
    )
    parser.add_argument(
        "-p",
        "--ports",
        help="Comma-separated list of ports or port ranges (e.g., 80,443,1000-2000)",
    )
    parser.add_argument(
        "-s",
        "--scan_type",
        choices=ThreadedNmapScanner.SCAN_TYPES.keys(),
        default=ThreadedNmapScanner.DEFAULT_SCAN_TYPE,
        help="""\
Scan type (default: OS Detection). Choose from:
1: SYN Scan (Stealth)
2: TCP Connect Scan
3: UDP Scan
4: FIN Scan (Stealth)
5: NULL Scan (Stealth)
6: Xmas Scan (Stealth)
7: ACK Scan (Firewall Detection)
8: Window Scan (Firewall Detection)
9: Maimon Scan (Firewall Detection)
10: Ping Scan (Host Discovery)
11: OS Detection
12: Aggressive Scan
13: Vulnerability Scan
14: Service Version Detection
""",
    )

    args = parser.parse_args()

    scanner = ThreadedNmapScanner(
        targets=args.targets, ports=args.ports, scan_type=args.scan_type
    )
    scanner.scan()
