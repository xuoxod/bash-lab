#!/usr/bin/python3


import os
import getpass
import netifaces
import logging
import subprocess  # For subprocess.run()
import threading  # For threading.Thread and threading.Lock
import time  # For time.sleep()
import errno  # For errno (used for error checking in threads)
import queue
import scapy

from scapy.all import *  #  Import all of Scapy
from scapy.all import IP, Ether, ARP, UDP, TCP, ICMP, srp
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from textcolors import TextColors
from queue import Queue, Empty
from networkexceptions import *
from helpers.netutil import NetUtil as netutil


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
        self.packet_queue = Queue(maxsize=1000)  # Initialize packet queue
        self.packet_queue_lock = threading.Lock()  # <--  Must be initialized here
        self.status_queue = Queue()  # Initialize status queue
        self.status_queue_lock = threading.Lock()  # <--  Must be initialized here
        self.reply_queue = Queue()
        self.reply_queue_lock = threading.Lock()

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
                raise DefaultInterfaceNotFoundError()  # More specific

            self._gateway_ip = self._get_default_gateway()
            self._own_ip = self._get_own_ip()
            self._own_mac = self._get_own_mac()

            # Check for None values and raise specific exceptions:
            if self._gateway_ip is None:
                raise GatewayNotFoundError()
            if self._own_ip is None:
                raise OwnIPNotFoundError()
            if self._own_mac is None:
                raise OwnMACNotFoundError()

        except (
            KeyError,
            IndexError,
            ValueError,
        ) as e:
            raise InterfaceConfigurationError(
                f"Error configuring interface: {e}"
            ) from e  # More specific
        except OSError as e:
            raise InterfaceError(f"OSError during initialization: {e}") from e

    def greet_user(self):
        """Presents a colorful greeting to the user, including network info."""
        username = getpass.getuser()
        greeting_table = Table(title=f"Welcome, {username}!", style="bold white")
        greeting_table.add_column(
            "Quick Summary", style="bold magenta", justify="center"
        )
        greeting_table.add_row("Network Tool Initialized", style="bold green")
        greeting_table.add_row(
            f"Interface: {self._interface or 'N/A'}", style="bold yellow"
        )  # Shows N/A if not available
        greeting_table.add_row(
            f"Gateway IP: {self._gateway_ip or 'N/A'}", style="bold blue"
        )
        greeting_table.add_row(f"Own IP: {self._own_ip or 'N/A'}", style="bold purple")
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

    #       Specific logic
    #######

    def _get_mac(self, ip_address):
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
                timeout=2,
                verbose=1,
            )
            if ans:
                return ans[0][1].hwsrc
            else:
                logger.error(f"Failed to resolve MAC address for {ip_address}")
                return None
        except Exception as e:
            logger.error(f"Error getting MAC address: {e}")
            raise AddressResolutionError(ip_address) from e  # Raise custom exception

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
                raise ARPRestorationError() from e  # Chain the exception
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

    def process_packet(self, packet):
        """Processes a captured packet."""

        def _process(packet):  # Internal packet processing function
            try:
                if IP in packet:
                    if packet[IP].dst == self.target_ip:
                        packet[Ether].dst = self.target_mac

                    elif packet[IP].src == self.target_ip:
                        packet[Ether].dst = self.gateway_mac

                    elif packet[IP].src == self._gateway_ip:
                        # Handle reverse traffic from gateway to target
                        packet[Ether].dst = self.target_mac

                    elif packet[IP].dst == self._gateway_ip:
                        packet[Ether].dst = self.gateway_mac

                    else:
                        # Packet not related to target or gateway
                        packet.show()
                        sendp(packet, verbose=0, iface=self._interface)

                    if self.use_scapy_forwarding:
                        sendp(packet, verbose=0, iface=self._interface)
                    else:  # System forwarding is active
                        logger.debug(
                            "System IP forwarding active; skipping Scapy processing."
                        )

                else:  # Handle non-IP packets
                    logger.debug(f"Non-IP packet received: {packet.summary()}")
                    if self.use_scapy_forwarding:
                        try:
                            sendp(packet, verbose=0, iface=self._interface)
                        except OSError as e:
                            logger.error(f"Error sending packet: {e}")

                with self.packet_queue_lock:
                    try:
                        self.packet_queue.put_nowait(packet.copy())
                        logger.info("Packet added to queue")
                    except queue.Full:
                        logger.warning("Packet queue is full. Dropping packet.")
                        raise PacketQueueFullError("Packet queue is full.")

            except Exception as e:
                logger.exception(f"Error processing packet: {e}")
                raise PacketProcessingError from e  # Reraise PacketProcessingError

        if packet:  # Only process if packet is not None
            _process(packet)  # Process the individual packet directly

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

    #       Sniffer logic
    #######

    def start_sniffer(self):  # Correct indentation
        """Starts the asynchronous sniffer."""
        if not hasattr(self, "sniffer") or not self.sniffer.running:
            conf.sniff_promisc = True  # Enable promiscuous mode here

            self.sniffer = AsyncSniffer(
                prn=self.process_packet, store=False, iface=self._interface
            )
            self.sniffer.start()

    def stop_sniffer(self):  # Correct indentation
        """Stops the asynchronous sniffer."""
        if hasattr(self, "sniffer") and self.sniffer.running:
            self.sniffer.stop()

    #       Packet logic
    #######

    def send_info_packet(self, dest_ip, dest_mac=None, use_udp=True, timeout=3):
        """Crafts, sends a packet, and handles replies asynchronously."""
        if not self.is_network_info_available():
            self.console.print(
                f"{TextColors.FAIL}Error: Network information not available.{TextColors.ENDC}",
                style="bold red",
            )
            return None

        scan_results = self.scan_network(dest_ip)  # ARP scan
        if scan_results is None:  # Handle ARP scan failure
            return None  # Return None

        # Initialize dest_mac - fixes problem where dest_mac might be undefined if not found from scan.
        dest_mac = None

        for result in scan_results:  # Find dest_mac in ARP scan results.
            if result["IP"] == dest_ip:
                dest_mac = result["MAC"]
                break  # Found MAC address

        if dest_mac is None:  # MAC address not found from ARP scan. Notify and return.
            self.console.print(
                f"[bold red]Could not resolve MAC address for {dest_ip} during scan.[/]"
            )
            return None  # Indicate failure
        else:
            self.console.print(
                f"\n\t[bold]Target's IP: {dest_ip} and MAC address: {dest_mac}[/]\n\n\n"
            )

            # Craft the information packet (using UDP or raw IP)
            if use_udp:  # UDP Packet
                marker = "NetworkOracle-InfoPacket"
                payload = (
                    marker + f"Interface: {self._interface}, ..."
                )  # Add marker to the beginning

                payload = f"Interface: {self._interface}, IP: {self._own_ip}, MAC: {self._own_mac}"

                packet = (
                    Ether(src=self._own_mac, dst=dest_mac)
                    / IP(src=self._own_ip, dst=dest_ip, flags="DF")
                    / UDP(sport=30660, dport=30770)
                    / payload
                )
            else:  # Raw IP Packet
                payload = bytes(
                    f"Raw Packet: Interface: {self._interface}, IP: {self._own_ip}, MAC: {self._own_mac}",
                    "utf-8",
                )
                packet = (
                    Ether(src=self._own_mac, dst=dest_mac)
                    / IP(src=self._own_ip, dst=dest_ip)
                    / payload
                )

            def handle_reply(reply):  # Correct nested callback
                """Handles replies/timeouts/errors and prints output."""

                if reply:
                    self.console.print(
                        Panel(
                            str(reply.summary()),
                            title="Packet Reply",
                            border_style="green",
                        )
                    )  # Print reply summary.

                elif isinstance(
                    reply, str
                ):  # String indicates an error from send_and_receive.
                    self.console.print(reply)  # Display error string from callback.
                else:
                    # Handle timeout (None) - no reply received.
                    self.console.print(
                        f"[bold yellow]No reply received from {dest_ip}[/]"
                    )

            try:
                if use_udp:
                    filter_str = f"udp and src host {dest_ip} and dst port 30660 and src port 30770 and dst host {self._own_ip}"  # Target IP, your port, Your IP
                else:  # Raw IP (must specify a protocol above IP if any)
                    filter_str = f"ip and src host {dest_ip} and dst host {self._own_ip}"  # Filter by source and destination IP

                answered, unanswered = srp(
                    packet,
                    timeout=timeout,
                    verbose=1,
                    iface=self._interface,
                    # filter=filter_str,
                    multi=True,  # Apply filter
                )

                for sent, received in answered:  # Examine each response.
                    self.console.print(
                        Panel(
                            str(received.summary()),
                            title="Packet Reply",
                            border_style="green",
                        )
                    )
                return answered  # Process the received packet

            except OSError as e:
                self.console.print(f"[bold red]Error sending packet: {e}[/]")
                return None  # Return None if send error

            except Exception as e:
                self.console.print(f"[bold red]Error: {e}[/]")
                return None  # Return None if receive error

    def send_and_receive(self, packet, callback=None):
        """Sends a packet and executes the callback with the result or error."""
        try:
            bpf_filter = self._build_reply_filter(packet)

            replies = sr1(
                packet, timeout=2, verbose=1, filter=bpf_filter, iface=self._interface
            )  # Correct sr1() call with filtering

            if callback:  # Always invoke the callback if one is provided
                callback(replies)
        except OSError as e:
            if callback:
                callback(
                    f"[bold red]OSError sending packet: {e}[/]"
                )  # Callback handles errors
        except Exception as e:
            if callback:
                callback(
                    f"[bold red]Error receiving packet: {e}[/]"
                )  # Callback handles errors

    def _build_reply_filter(self, packet):
        """Builds a BPF filter to capture a wider range of replies."""
        return f"(src host {packet[IP].dst}) or (dst host {packet[IP].src} and (icmp or udp or tcp))"

    def scan_network(
        self, target_ip
    ):  # Remove threading logic from here. method should block until reply.
        """Sends ARP requests and returns IP-MAC mappings."""
        try:
            ans, unans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip),
                timeout=2,
                verbose=1,
                iface=self._interface,
            )  # Use srp() for multiple responses
            results = []
            for sent, received in ans:  # Process replies
                results.append({"IP": received.psrc, "MAC": received.hwsrc})
            return results  # Return results or None

        except Exception as e:
            self.console.print(
                f"[bold red]Error during network scan: {e}[/]"
            )  # Show any errors from network scan.
            return None  # Indicate failure
