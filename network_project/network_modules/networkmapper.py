#!/usr/bin/python3

import argparse
import ipaddress
import netifaces
import threading
import queue
from typing import List, Tuple

from scapy.all import ARP, Ether, srp


class TextColors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    # New colors
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    LIGHT_YELLOW = "\033[1;33m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_MAGENTA = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"


class NetworkMapper:
    def __init__(self, interface: str = None):
        self.interface = interface or self._get_default_interface()
        self.own_ip = self.get_ip_address()
        # self.own_mac = self.get_mac_address(self.own_ip)
        self.lock = threading.Lock()  # Lock for thread-safe operations

        # Mental Debug: Get own MAC from interface info
        try:
            # netifaces gets all interface data
            iface_data = netifaces.ifaddresses(self.interface)
            # AF_LINK is for link layer (MAC)
            link_data = iface_data[netifaces.AF_LINK]
            # First entry should be our MAC
            self.own_mac = link_data[0]["addr"]
        except (ValueError, KeyError, IndexError) as e:
            self.print_error(f"Error getting own MAC address: {e}")
            self.own_mac = None

    def _get_default_interface(self) -> str:
        """Gets the default network interface."""
        try:
            gws = netifaces.gateways()
            default_gateway = gws["default"][netifaces.AF_INET]
            return default_gateway[1]  # Interface name
        except Exception as e:
            self.print_error(f"Error getting default interface: {e}")
            return None

    def get_ip_address(self) -> str:
        """Gets the IP address of the specified interface."""
        try:
            return netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]["addr"]
        except Exception as e:
            self.print_error(
                f"Error getting IP address for interface {self.interface}: {e}"
            )
            return None

    def get_mac_address(self, ip_address: str) -> str:
        """Gets the MAC address for a given IP address using ARP."""
        try:
            arp_request = ARP(pdst=ip_address)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = srp(
                arp_request_broadcast, timeout=2, verbose=False, iface=self.interface
            )[0]
            if answered_list:
                return answered_list[0][1].hwsrc
            else:
                return None
        except Exception as e:
            self.print_error(f"Error getting MAC address for {ip_address}: {e}")
            return None

    def _scan_target(self, target: str) -> Tuple[str, str]:
        """Scans a single target IP and returns a (IP, MAC) tuple."""
        mac = self.get_mac_address(target)
        if mac:
            with self.lock:  # Acquire lock before printing
                print(f"{TextColors.OKCYAN}IP: {target}\tMAC: {mac}{TextColors.ENDC}")
            return target, mac
        return None, None

    def scan_targets(self, targets: List[str]) -> List[Tuple[str, str]]:
        """Scans a list of target IPs using threading."""
        results = []
        threads = []
        result_queue = queue.Queue()  # Create a queue to store results

        for target in targets:
            try:
                # Mental Debug: Check if it's a CIDR
                network = ipaddress.ip_network(target, strict=False)
                # If it's a CIDR, scan each IP in the network
                for ip in network.hosts():
                    ip_str = str(ip)
                    thread = threading.Thread(
                        target=lambda t: result_queue.put(self._scan_target(t)),
                        args=(ip_str,),
                    )
                    threads.append(thread)
                    thread.start()
            except ValueError:
                # Mental Debug: If not a CIDR, treat as a single IP
                thread = threading.Thread(
                    target=lambda t: result_queue.put(self._scan_target(t)),
                    args=(target,),
                )
                threads.append(thread)
                thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Get results from the queue
        while not result_queue.empty():
            ip, mac = result_queue.get()
            if ip and mac:  # Only append if both are not None
                results.append((ip, mac))

        return results

    def print_results(self, results: List[Tuple[str, str]]):
        """Prints the scan results with formatting and colors."""
        print(
            f"\n{TextColors.BOLD}{TextColors.OKGREEN}Network Mapping Results:{TextColors.ENDC}"
        )
        print(f"{TextColors.OKBLUE}-{TextColors.ENDC}" * 50)
        print(
            f"{TextColors.OKBLUE}Interface: {self.interface}  (Own IP: {self.own_ip}, MAC: {self.own_mac}){TextColors.ENDC}"
        )
        print(f"{TextColors.OKBLUE}-{TextColors.ENDC}" * 50)

        if results:
            # Results are printed in _scan_target as they are found
            pass
        else:
            print(f"{TextColors.WARNING}No active hosts found.{TextColors.ENDC}")
        print(f"{TextColors.OKBLUE}-{TextColors.ENDC}" * 50)

    def print_status(self, message: str):
        print(f"{TextColors.OKGREEN}[+] {message}{TextColors.ENDC}")

    def print_error(self, message: str):
        print(f"{TextColors.FAIL}[!] {message}{TextColors.ENDC}")


def main():
    """Parses arguments and runs the network mapping."""
    parser = argparse.ArgumentParser(
        description="""
        NetworkMapper: A tool to map IP addresses to MAC addresses on your network.
        This tool can be used standalone or imported as a module in other Python scripts.
        """,
        epilog="""
        Examples:
          python network_mapper.py 192.168.1.1 192.168.1.10 192.168.1.20
          python network_mapper.py 192.168.1.0/24 -i eth1
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="""IP addresses or CIDR ranges to scan. 
        Separate multiple targets with spaces. 
        Example: 192.168.1.1 192.168.1.10-192.168.1.20 192.168.2.0/24""",
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to use (optional). If not provided, the default interface will be used.",
    )

    args = parser.parse_args()

    mapper = NetworkMapper(args.interface)
    results = mapper.scan_targets(args.targets)
    mapper.print_results(results)


if __name__ == "__main__":
    main()
