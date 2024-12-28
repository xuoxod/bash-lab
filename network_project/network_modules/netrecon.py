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


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
console = Console()


class NetRecon:
    def __init__(self, nmap_path="nmap"):
        self.nmap_path = nmap_path
        self.default_interface = self._get_default_interface()
        if not self.default_interface:
            raise RuntimeError("Could not determine default network interface.")

    def _get_default_interface(self):
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][1]
        except (KeyError, IndexError):
            return None

    async def _get_mac_address(self, ip_address):
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
                timeout=2,
                verbose=False,
                iface=self.default_interface,
            )
            return ans[0][1].hwsrc if ans else None
        except OSError as e:
            logger.error(f"Error during ARP scan for {ip_address}: {e}")
            return None

    def _get_os_info(self, host_element):  # Improved OS info extraction
        os_info = {}
        os_el = host_element.find("os")
        if os_el is not None:
            osclass_el = os_el.find("osclass")
            if osclass_el is not None:
                os_info = {
                    "name": osclass_el.get("name"),
                    "type": osclass_el.get("type"),
                    "vendor": osclass_el.get("vendor"),
                    "family": osclass_el.get("osfamily"),
                    "generation": osclass_el.get("osgen"),
                }
            elif (
                os_el.find("osmatch") is not None
            ):  # Consider osmatch if osclass is not found
                osmatch_el = os_el.find("osmatch")
                os_info = {"osfamily": osmatch_el.get("name")}
        return os_info

    def _get_os_info_old(
        self, host_element
    ):  # Improved OS info extraction with None checks
        os_info = {}
        os_el = host_element.find("os")
        if os_el is not None:
            osclass_el = os_el.find("osclass")
            if osclass_el is not None:
                os_info = {
                    "type": osclass_el.get("type"),
                    "vendor": osclass_el.get("vendor"),
                    "family": osclass_el.get("osfamily"),
                    "generation": osclass_el.get("osgen"),
                }
        return os_info

    async def _port_scan(self, target, ports):
        if not shutil.which(self.nmap_path):
            logger.error(f"Nmap executable not found at: {self.nmap_path}")
            return None

        try:
            process = await asyncio.create_subprocess_exec(
                self.nmap_path,
                "-oX",
                "-",
                "-p",
                ",".join(map(str, ports)),
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            if stderr:
                logger.error(f"Nmap error: {stderr.decode()}")
                return None

            return ET.fromstring(stdout.decode())  # Return parsed XML directly

        except ET.ParseError:  # Handle invalid XML
            logger.error(f"Invalid XML output from Nmap scan for {target}")
            return None
        except Exception as e:
            logger.exception(f"Unexpected error during port scan: {e}")
            return None

    def _extract_host_info(self, host_element):  # Optimized host info extraction
        host_info = {}

        address_el = host_element.find('.//address[@addrtype="ipv4"]')
        host_info["ip"] = address_el.get("addr") if address_el is not None else None

        host_info["hostname"] = ""
        hostnames_el = host_element.find("hostnames")

        if hostnames_el is not None:
            hostname_el = hostnames_el.find("hostname")
            host_info["hostname"] = (
                hostname_el.get("name") if hostname_el is not None else ""
            )
        host_info["os"] = self._get_os_info(host_element)

        open_ports = []
        ports_el = host_element.find("ports")

        if ports_el is not None:
            for port in ports_el.findall("port"):
                state_el = port.find("state")

                if state_el is not None and state_el.get("state").lower() == "open":
                    port_info = {
                        "portid": int(port.get("portid")),
                        "service": (
                            port.find("service").get("name")
                            if port.find("service") is not None
                            else ""
                        ),  # Extract service name, handle missing service
                    }
                    open_ports.append(port_info)

        host_info["open_ports"] = open_ports
        return host_info

    async def scan(self, network, ports):

        try:
            network = ipaddress.ip_network(network, strict=False)
            target_ips = network.hosts()  # Get all hosts in the network

        except ValueError:  #  Handle single IP
            try:
                ipaddress.ip_address(network)  # Validate that it is indeed an IP
                target_ips = [
                    ipaddress.ip_address(network)
                ]  # Put single IP into list for consistent iteration below
            except ValueError as e:
                console.print(f"[bold red]Error: Invalid network/IP address: {e}[/]")
                return []

        all_results = []

        for ip in target_ips:  # Iterate over the list of target IPs
            ip_str = str(ip)
            mac = await self._get_mac_address(ip_str)
            current_result = {"ip": ip_str, "mac": mac or "Unknown"}

            nmap_xml_root = await self._port_scan(ip_str, ports)

            if nmap_xml_root:
                nmap_host_found = False  # Flag to indicate Nmap data was merged
                for host_element in nmap_xml_root.findall("host"):
                    host_info = self._extract_host_info(host_element)
                    if host_info and host_info.get("ip") == ip_str:
                        current_result.update(host_info)
                        nmap_host_found = True
                        break  # Done processing for this IP from the Nmap results. Prevents duplicates from multiple host blocks in Nmap XML

                if nmap_host_found:
                    all_results.append(
                        current_result
                    )  # Append only after Nmap processing for this IP address.
                else:
                    all_results.append(
                        current_result
                    )  # if Nmap data is not added to current_result, then current_result only contains ARP scan results (at this point).

            else:  # No Nmap results found for this particular IP address. Add ARP results.
                all_results.append(current_result)

        return all_results

    async def run_scan(self, network, ports):  # Correctly displays output.
        results = await self.scan(network, ports)

        with PrettyPrint(title="[bold bright_blue]Network Scan Results[/]") as pp:
            pp.add_column("IP Address", style="green")
            pp.add_column("MAC Address", style="cyan")
            pp.add_column("Hostname", style="magenta")
            pp.add_column("OS", style="white")
            pp.add_column("Open Ports", style="yellow")

            for result in results:
                ip_address = result.get("ip")
                mac_address = result.get("mac", "Unknown")
                hostname = result.get("hostname", "Unknown")
                os_info = result.get("os", {})
                os_str = (
                    f"{os_info.get('vendor', '')} {os_info.get('family', '')} {os_info.get('generation', '')}"
                    or "Unknown"
                )  # Corrected OS string formatting
                open_ports_info = result.get("open_ports", [])
                open_ports_str = (
                    ", ".join(
                        f"{p.get('portid')}/{p.get('service', '')}"
                        for p in open_ports_info
                    )
                    if open_ports_info
                    else "None"
                )  # Corrected output formatting.

                # OS info is now displayed correctly.
                os_info = result.get("os", {})
                os_str = (
                    f"{os_info.get('vendor', '')} {os_info.get('family', '')} {os_info.get('generation', '')} {os_info.get('type', '')}"  # Include "type" in the OS string. Also include osfamily in case type, vendor, family, generation are not found.
                    or f"{os_info.get('osfamily','')} "  # Or Unknown OS if all other OS fields are missing.
                    or "Unknown OS"  # Default if both dictionary and osfamily are missing
                )

                pp.add_row(ip_address, mac_address, hostname, os_str, open_ports_str)


def main():
    parser = argparse.ArgumentParser(
        description="Network reconnaissance tool. Performs ARP and Nmap scans.",
        epilog="Examples:\n"  # Updated example
        "  netrecon 192.168.1.0/24 -p 22,80,443  Scan network 192.168.1.0/24 for ports 22, 80, and 443\n"
        "  netrecon 192.168.1.100 -p 22,80 Scan a single host (192.168.1.100) for ports 22 and 80\n"  # Added port option to the single host example.
        "  netrecon 192.168.1.1-192.168.1.10 -p 20-100 Scan an IP range for ports 20-100\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "network", help="Network CIDR, IP address, or IP range to scan."
    )
    parser.add_argument(
        "-p",
        "--ports",
        required=True,
        help="Comma-separated list of ports to scan (e.g., 22,80,443,20-100).",
    )  # Ports are now required.

    args = parser.parse_args()  # args is now defined within main's scope

    try:
        ports = []
        for port_range in args.ports.split(","):
            if "-" in port_range:
                start, end = map(int, port_range.split("-"))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(port_range))

    except ValueError:
        console.print(
            "[bold red]Error: Invalid port format.  Use comma separated ports and/or ranges like 22,80,20-100[/]"
        )
        return

    net_recon = NetRecon()

    try:
        asyncio.run(net_recon.run_scan(args.network, ports))  # Now 'args' is defined.
    except KeyboardInterrupt:
        print("\nScan interrupted.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
