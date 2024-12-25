#!/usr/bin/python3

import argparse
import asyncio
import json
import logging
import os
import ipaddress
import shutil
from typing import List
import netifaces
import subprocess
import xml.etree.ElementTree as ET
import csv
from scapy.all import ARP, Ether, srp, conf

logger = logging.getLogger(__name__)


class Netreconnoiter:
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
        "SYN": "-sS",
        "NULL": "-sN",
        "FIN": "-sF",
        "XMAS": "-sX",
        "ACK": "-sA",
        "WINDOW": "-sW",
        "MAIMON": "-sM",
        "UDP": "-sU",
        "TCP": "-sT",
        "IDLE": "-sI",
        "SCTP": "-sS",
        "OS": "-O",
        "SCRIPT": "-sC",
        "BET": "--badsum",
        "CONNECT": "-sT",
    }

    DEFAULT_SCAN_TYPE = "SYN"

    def __init__(
        self,
        interface: str = None,
        targets: List[str] = None,
        ports: List[str] = None,
        scan_type: str = DEFAULT_SCAN_TYPE,
        nmap_path: str = "nmap",
        threads: int = 10,
        quiet: bool = False,
        log_file: str = None,
    ):
        self.interface = interface or self._get_default_interface()  # Get interface

        if not self.interface:
            raise ValueError(
                "No network interface specified and could not determine a default interface."
            )  # No interface found; stop.

        self.targets = self._parse_targets(targets) if targets else []

        if not self.targets:
            raise ValueError("No valid scan targets specified.")

        self.ports = self._parse_ports(ports) if ports else self.COMMON_PORTS
        self.scan_type = (
            scan_type if scan_type and scan_type != "help" else self.DEFAULT_SCAN_TYPE
        )
        self.nmap_path = nmap_path
        self.threads = threads
        self.quiet = quiet
        self.log_file = log_file

        self.own_ip = None
        self.own_mac = None

        self.setup_logging()  # Set up logging after initializing attributes

    def setup_logging(self):
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        if self.log_file:
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

        if not self.quiet:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        elif not self.log_file:  # If quiet and no log file, disable logging.
            logger.addHandler(logging.NullHandler())

    def _get_default_interface(self):  # Corrected: No redundancy
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][1]
        except (KeyError, IndexError):
            return None

    def _get_ip_address(self):  # Corrected: No redundancy
        try:
            addresses = netifaces.ifaddresses(self.interface)
            return addresses[netifaces.AF_INET][0]["addr"]
        except (KeyError, IndexError, ValueError, OSError) as e:
            if not self.quiet:  # Only log to console if not quiet
                logger.error(f"Could not get IP for interface: {self.interface}. {e}")
            return None

    async def _get_mac_address(self, ip_address):  # Corrected: No redundancy
        if not ip_address:
            logger.error("IP not provided for MAC lookup.")
            return None
        try:
            conf.verb = 0
            ans, unans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
                timeout=2,
                verbose=False,
                iface=self.interface,
            )
            return ans[0][1].hwsrc if ans else None
        except OSError as e:
            if not self.quiet:
                logger.error(f"Error during ARP scan: {e}")
            return None

    def _parse_targets(self, targets_str):
        targets = []
        for target_str in targets_str:
            try:
                ip = ipaddress.ip_address(target_str)
                targets.append(str(ip))
            except ValueError:
                try:
                    network = ipaddress.ip_network(target_str, strict=False)
                    for ip in network.hosts():
                        targets.append(str(ip))
                except ValueError:
                    if not self.quiet:
                        logger.error(f"Invalid target: {target_str}. Skipping.")
        return targets

    def _parse_ports(self, ports_str):
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
                            logger.warning(
                                f"Invalid port range: {port_range}. Port numbers must be between 0 and 65535."
                            )
                    else:
                        port = int(port_range)
                        if 0 <= port <= 65535:
                            ports.append(port)
                        else:
                            logger.warning(
                                f"Invalid port number: {port}. Port number must be between 0 and 65535."
                            )
                except ValueError:
                    logger.warning(f"Invalid port specification: {port_range}")
        return [str(p) for p in ports]

    async def _execute_nmap_scan(self, target, ports, scan_type):
        if not shutil.which(self.nmap_path):
            raise FileNotFoundError(f"Nmap executable not found at: {self.nmap_path}")

        try:
            nmap_args = [self.nmap_path, "-oX", "-"]

            if ports:
                nmap_args.extend(["-p", ",".join(map(str, ports))])

            if scan_type:
                nmap_scan_type_arg = self.SCAN_TYPES.get(scan_type.upper())
                if nmap_scan_type_arg:
                    nmap_args.append(nmap_scan_type_arg)
                else:
                    logger.error(f"Invalid Nmap scan type: {scan_type}. Using default.")

            nmap_args.append(target)

            process = await asyncio.create_subprocess_exec(
                *nmap_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                decoded_stderr = stderr.decode()
                error_message = f"Nmap scan for {target} failed:\n{decoded_stderr}"
                logger.error(error_message)
                raise subprocess.CalledProcessError(
                    process.returncode, nmap_args, output=stdout, stderr=stderr
                )

            return stdout.decode()

        except Exception as e:
            logger.exception(f"An unexpected error occurred during Nmap execution: {e}")
            return None

    def _process_nmap_output(self, nmap_output):
        try:
            root = ET.fromstring(nmap_output)

            if not root.findall("host"):  # Handle cases where no hosts are found
                if not self.quiet:  # Respect quiet mode
                    logger.warning("No hosts found in Nmap scan results.")
                return []

            scan_results = []
            for host in root.findall("host"):
                host_info = {}

                address_element = host.find("address[@addrtype='ipv4']")
                host_info["ip_address"] = (
                    address_element.get("addr") if address_element is not None else None
                )

                hostname_element = host.find("hostnames/hostname[@name]")
                host_info["hostname"] = (
                    hostname_element.get("name")
                    if hostname_element is not None
                    else None
                )

                host_info["os"] = self._parse_os_info(host)

                ports_element = host.find("ports")
                if ports_element is not None:
                    ports = []
                    for port in ports_element.findall("port"):
                        state_element = port.find("state")
                        service_element = port.find("service")
                        port_info = {
                            "protocol": port.get("protocol"),
                            "portid": int(port.get("portid")),
                            "state": (
                                state_element.get("state")
                                if state_element is not None
                                else None
                            ),
                            "service": (
                                service_element.get("name")
                                if service_element is not None
                                else None
                            ),
                            "version": (
                                f"{service_element.get('product', '')} {service_element.get('version', '')}".strip()
                                if service_element is not None
                                else ""
                            ),
                        }
                        ports.append(port_info)
                    host_info["ports"] = ports
                else:
                    host_info["ports"] = []

                scan_results.append(host_info)

            return scan_results

        except ET.ParseError as e:
            logger.error(f"Error parsing Nmap XML: {e}")
            return None

        except Exception as e:
            logger.exception(f"Unexpected error in processing Nmap output: {e}")
            return None

    def _parse_os_info(self, host):  # Corrected logic:  Use setdefault.
        os_info = {}
        os_element = host.find("os")

        if os_element is not None:
            osmatch_element = os_element.find("osmatch")
            if osmatch_element is not None:
                os_info["osfamily"] = osmatch_element.get("name")
                os_info["osgen"] = osmatch_element.get("accuracy")

            osclass_element = os_element.find("osclass")  # Always try to get osclass
            if osclass_element is not None:
                os_info["type"] = osclass_element.get("type")
                os_info["vendor"] = osclass_element.get("vendor")
                os_info.setdefault(
                    "osfamily", osclass_element.get("osfamily")
                )  # Use setdefault.  Don't overwrite existing values.
                os_info.setdefault(
                    "osgen", osclass_element.get("osgen")
                )  # Use setdefault. Don't overwrite existing values.

        return os_info

    async def _arp_scan(self, target):
        try:
            ans, unans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target),
                timeout=2,
                verbose=False,
                iface=self.interface,
            )
            return (
                {"ip_address": target, "mac_address": ans[0][1].hwsrc} if ans else None
            )
        except OSError as e:
            if not self.quiet:
                logger.error(f"Error during ARP scan for {target}: {e}")
            return None

    async def scan(self):
        self.own_ip = self._get_ip_address()
        if not self.own_ip:
            raise ValueError(
                f"Could not obtain IP address for interface {self.interface}"
            )

        self.own_mac = await self._get_mac_address(self.own_ip)

        results = {}

        arp_tasks = [self._arp_scan(target) for target in self.targets]
        arp_results = await asyncio.gather(*arp_tasks)

        if self.nmap_path:  # Only run nmap tasks if we have nmap available.
            nmap_tasks = [
                self._execute_nmap_scan(target, self.ports, self.scan_type)
                for target in self.targets
            ]
            nmap_outputs = await asyncio.gather(*nmap_tasks)

        for arp_result in arp_results:
            if arp_result:
                results[arp_result["ip_address"]] = arp_result

        if self.scan_type != "help":
            nmap_tasks = [
                self._execute_nmap_scan(target, self.ports, self.scan_type)
                for target in self.targets
            ]
            nmap_outputs = await asyncio.gather(*nmap_tasks)

            for nmap_output, target in zip(nmap_outputs, self.targets):
                if nmap_output:
                    nmap_results = self._process_nmap_output(nmap_output)
                    if nmap_results:
                        for nmap_result in nmap_results:
                            ip = nmap_result.get("ip_address")
                            if ip:  # Only add/update if IP is present
                                if ip in results:
                                    results[ip].update(nmap_result)
                                else:
                                    results[ip] = nmap_result

        return list(results.values())

    def print_results(self, results):
        if not self.quiet:
            print("-" * 70)
            print(
                f"{'IP Address':<15} {'MAC Address':<20} {'Hostname':<25} {'OS':<20} {'Open Ports/Service':<30}"
            )
            print("-" * 70)

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
                        f"{port['portid']}/{port['service']} ({port['version']})"
                        for port in result.get("ports", [])
                        if port.get("state") == "open"
                    ]
                )
                print(
                    f"{ip_address:<15} {mac_address:<20} {hostname:<25} {os_string:<20} {open_ports_services:<30}"
                )

    def save_results(self, results, filename="scan-results.json", json_format=False):
        try:
            if json_format:
                with open(filename, "w") as f:
                    json.dump(results, f, indent=4)
            else:  # CSV Format
                if not filename.lower().endswith(".csv"):
                    filename += ".csv"
                with open(filename, "w", newline="", encoding="utf-8") as csvfile:
                    fieldnames = [
                        "IP Address",
                        "MAC Address",
                        "Hostname",
                        "OS Family",
                        "OS Generation",
                        "OS Vendor",
                        "Open Ports",
                    ]
                    writer = csv.DictWriter(
                        csvfile, fieldnames=fieldnames, extrasaction="ignore"
                    )
                    writer.writeheader()
                    for result in results:
                        os_info = result.get("os", {})
                        ports = result.get("ports", [])
                        open_ports_str = ", ".join(
                            [
                                str(p["portid"])
                                for p in ports
                                if p.get("state") == "open"
                            ]
                        )
                        writer.writerow(
                            {
                                "IP Address": result.get("ip_address", ""),
                                "MAC Address": result.get("mac_address", ""),
                                "Hostname": result.get("hostname", ""),
                                "OS Family": os_info.get("osfamily", ""),
                                "OS Generation": os_info.get("osgen", ""),
                                "OS Vendor": os_info.get("vendor", ""),
                                "Open Ports": open_ports_str,
                            }
                        )
            logger.info(f"Scan results saved to: {filename}")

        except OSError as e:
            logger.error(f"Error saving results to file: {e}")
        except Exception as e:
            logger.exception(f"An unexpected error occurred during saving: {e}")


def print_scan_types(scan_types):
    print("Available Scan Types:")
    for scan_type in scan_types:
        print(scan_type)


async def main():
    parser = argparse.ArgumentParser(
        description="Network scanner using ARP and Nmap.",
        epilog="See -h for examples.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-i", "--interface", help="Network interface for scanning.")
    parser.add_argument("targets", nargs="*", help="Target IPs, CIDRs, or hostnames.")
    parser.add_argument("-p", "--ports", help="Comma-separated ports or ranges.")
    parser.add_argument(
        "-s",
        "--scan_type",
        choices=list(Netreconnoiter.SCAN_TYPES.keys()) + ["help"],
        default=Netreconnoiter.DEFAULT_SCAN_TYPE,
        help="Nmap scan type. Use -st for available types.",
    )
    parser.add_argument(
        "--nmap-path", default="nmap", help="Path to the Nmap executable."
    )
    parser.add_argument(
        "-st",
        "--show_scan_types",
        action="store_true",
        help="Display available Nmap scan types.",
    )
    parser.add_argument(
        "-O", "--os-detection", action="store_true", help="Enable OS detection."
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of threads for ARP scan (currently unused).",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Quiet mode. Suppress output."
    )
    parser.add_argument("--log-file", help="Path to log file.")
    parser.add_argument(
        "--json", action="store_true", help="Save results in JSON format."
    )

    args = parser.parse_args()

    if args.show_scan_types or args.scan_type == "help":
        print_scan_types(Netreconnoiter.SCAN_TYPES)
        return

    scan_type = "OS" if args.os_detection else args.scan_type

    if args.threads <= 0:  # Validate the threads argument
        logger.error("Number of threads must be greater than 0.")
        return

    try:
        scanner = Netreconnoiter(
            args.interface,
            args.targets,
            args.ports,
            scan_type,
            args.nmap_path,
            args.threads,
            args.quiet,
            args.log_file,
        )
        scan_results = await scanner.scan()

        if scan_results:
            scanner.print_results(scan_results)
            filename = "scan-results.json" if args.json else "scan-results.csv"
            scanner.save_results(scan_results, filename=filename, json_format=args.json)
        elif not scanner.quiet:  # Respect quiet mode when logging.
            logger.warning("No results found.")

    except ValueError as e:
        logger.error(e)  # Log the ValueError
        parser.print_help()  # And show help message, more user-friendly
    except FileNotFoundError as e:
        logger.error(e)
    except KeyboardInterrupt:
        print("\nScan interrupted.")
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    asyncio.run(main())
