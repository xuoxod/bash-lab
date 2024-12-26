#!/usr/bin/python3

import argparse
import ipaddress
import logging
import asyncio
import netifaces
import subprocess
import xml.etree.ElementTree as ET
import shutil

from typing import List, Dict
from rich.console import Console
from scapy.all import *
from prettyprint import PrettyPrint
from textcolors import TextColors

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

console = Console()


class NetRecon:
    def __init__(self, nmap_path="nmap"):
        self.nmap_path = nmap_path
        self.default_interface = self._get_default_interface()
        if self.default_interface is None:
            raise RuntimeError("Could not determine default network interface.")

    def _get_default_interface(self):
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][1]
        except:
            return None

    async def _get_mac_address(self, ip_address):
        try:
            ans, unans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
                timeout=2,
                verbose=False,
                iface=self.default_interface,
            )
            return ans[0][1].hwsrc if ans else None
        except OSError as e:
            logger.error(f"Error during ARP scan for {ip_address}: {e}")
            return None

    async def _arp_scan(self, target):
        return await self._get_mac_address(target)

    async def _port_scan(self, target, ports):
        if not shutil.which(self.nmap_path):
            logger.error(f"Nmap executable not found at: {self.nmap_path}")
            return None

        try:
            nmap_process = await asyncio.create_subprocess_exec(
                self.nmap_path,
                "-oX",
                "-",
                "-p",
                ",".join(ports),
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await nmap_process.communicate()

            if stderr:
                logger.error(f"Nmap error: {stderr.decode()}")
                return None

            return stdout.decode()
        except Exception as e:
            logger.exception(f"Unexpected error during port scan: {e}")
            return None

    def _parse_nmap_output(self, nmap_xml_output):
        """Parses Nmap XML output."""

        try:
            root = ET.fromstring(nmap_xml_output)
            results = []

            for host in root.findall("host"):
                host_info = {}

                address_el = host.find(
                    './/address[@addrtype="ipv4"]'
                )  # find from root down for ipv4 address
                host_info["ip"] = (
                    address_el.get("addr") if address_el is not None else None
                )

                host_info["hostname"] = ""  # Initialize for consistency
                hostnames_el = host.find("hostnames")
                if hostnames_el is not None:
                    hostname_el = hostnames_el.find("hostname")
                    if hostname_el is not None:
                        host_info["hostname"] = hostname_el.get("name")

                host_info["os"] = (
                    self._get_os_info(host) or {}
                )  # handle missing "os" gracefully
                host_info["ports"] = []  # Initialize even if no ports are found.

                ports_el = host.find("ports")
                if ports_el is not None:
                    for port in ports_el.findall("port"):
                        port_info = {}
                        state_el = port.find("state")

                        port_info["state"] = (
                            state_el.get("state") if state_el is not None else None
                        )
                        port_info["portid"] = (
                            int(port.get("portid")) if port.get("portid") else None
                        )

                        service_el = port.find("service")  # add service information
                        if service_el is not None:
                            port_info["service"] = service_el.get("name", "")

                        host_info["ports"].append(port_info)
                results.append(host_info)
            return (
                results or []
            )  # Return results (or empty list to avoid NoneType errors)

        except ET.ParseError:
            logger.error("Invalid Nmap XML output.")
            return None  # Return None to signal parsing failure.

        except Exception as e:
            logger.exception(f"Error parsing Nmap output: {e}")
            return None  # Return None on any other exception.

    def _get_os_info(self, host):
        os_info = {}
        os_el = host.find("os")
        if os_el is not None:
            osclass_el = os_el.find(
                "osclass"
            )  # prefer osclass to osmatch as per documentation
            if osclass_el is not None:
                os_info = {
                    "type": osclass_el.get("type"),
                    "vendor": osclass_el.get("vendor"),
                    "family": osclass_el.get("osfamily"),
                    "generation": osclass_el.get("osgen"),
                }
        return os_info

    async def scan(self, network, ports=None):
        """Scans the given network.  Expects a list of validated ports, or None"""
        try:
            network = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            console.print(f"[bold red]Error: Invalid network address: {e}[/]")
            return []

        all_results = []
        for ip in network.hosts():
            ip_str = str(ip)
            mac = await self._arp_scan(ip_str)
            result = {"ip": ip_str, "mac": mac or "Unknown"}

            if ports:  # Perform port scan only if ports are provided
                nmap_result = await self._port_scan(ip_str, ports)
                if nmap_result:
                    result["nmap_data"] = self._parse_nmap_output(nmap_result)

            all_results.append(result)  # Always append, even without Nmap data

        return all_results


async def run_scan(net_recon_instance, network, ports):
    """Handles port parsing, performs the scan, and outputs the results."""

    try:  # Validate network *before* port parsing
        network = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        console.print(f"[bold red]Error: Invalid network address: {e}[/]")
        return

    ports_set = set()
    ports_list = []  # The validated parsed ports list

    if ports:  # Only try to parse if ports are specified.
        for port_str in ports.split(","):
            port = port_str.strip()  # Handle potential spaces after commas
            if port and port.isdigit():
                port = int(port)
                if 0 <= port <= 65535 and port not in ports_set:
                    ports_set.add(port)
                    ports_list.append(str(port))  # Correctly add the valid ports
                # ... (handle duplicate/invalid ports as before)

    valid_ports = (
        ports_list if ports_list else None
    )  # Assign ports_list or None for scan()

    results = await net_recon_instance.scan(
        network, valid_ports
    )  # Use validated ports or None if none specified and valid

    with PrettyPrint(title="[bold bright_cyan]Network Scan Results[/]") as pp:
        pp.add_column("IP Address", style="green")
        pp.add_column("MAC Address", style="cyan")
        pp.add_column("Hostname", style="magenta")
        pp.add_column("OS", style="blue")
        pp.add_column("Open Ports", style="yellow")

        for result in results:
            nmap_data = result.get("nmap_data", [])  # Handle missing nmap_data
            host_info = next(
                (h for h in nmap_data if h.get("ip") == result["ip"]), {}
            )  # Fix - Extract host_info by matching IP

            os_str = (
                f"{host_info.get('os', {}).get('vendor', '')} {host_info.get('os', {}).get('family', '')} {host_info.get('os', {}).get('generation', '')}"
                if host_info.get("os")
                else "Unknown"
            )

            open_ports = (
                ", ".join(
                    str(p.get("portid"))
                    for p in host_info.get("ports", [])  # Handle missing "ports" key
                    if p.get("state", {}).lower() == "open"
                )
                if host_info.get("ports")  # Check for "ports" Key.
                else None
            )

            pp.add_row(
                result["ip"],
                result.get("mac", "Unknown"),
                host_info.get("hostname", ""),
                os_str,
                open_ports,
            )


def main():
    parser = argparse.ArgumentParser(
        description="Network reconnaissance tool. Performs ARP and Nmap scans.",
        epilog="Examples:\n"
        "  netrecon 192.168.1.0/24 -p 22,80,443  Scan network 192.168.1.0/24 for ports 22, 80, and 443\n"
        "  netrecon 192.168.1.100           Scan a single host (192.168.1.100)\n"
        "  netrecon 192.168.1.1-192.168.1.10  Scan an IP range\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "network", help="Network CIDR, IP address, or IP range to scan."
    )
    parser.add_argument(
        "-p",
        "--ports",
        help="Comma-separated list of ports to scan (e.g., 22,80,443). "
        "If not specified, no port scan will be performed.",  # Clarify this.
    )

    args = parser.parse_args()

    net_recon = NetRecon()

    try:
        asyncio.run(run_scan(net_recon, args.network, args.ports))
    except KeyboardInterrupt:
        print("\nScan interrupted.")
    except Exception as e:  # More general exception handling.
        print(f"An unexpected error occurred: {e}")  # Catch and report any error.


if __name__ == "__main__":
    main()
