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
from packetsaver import PacketSaver  # Correct import - no "as psaver" needed


class Rerouter:
    # ... (__init__ method - same as corrected version in previous response)

    # ... (_get_default_interface, _get_default_gateway - same as before)

    def _get_ip_address(self, ifname):  # Completed in the last response - included here for completeness
        """Gets the IP address associated with a given interface name."""
        try:
            addrs = netifaces.ifaddresses(ifname)
            return addrs[netifaces.AF_INET][0]["addr"]
        except (KeyError, IndexError, ValueError) as e:
            self._print_error(f"Could not get IP address for {ifname}: {e}")
            return None



    # ... (_enable_ip_forwarding, _disable_ip_forwarding, _print_status, _print_error, _update_table - same as before)


    def _get_mac(self, ip_address):  # Same robust implementation as before
        # ... (Implementation from previous response - handles retries and errors)


    def _poison_target(self):  # Corrected in previous responses
        # ... (Implementation from previous response - handles stop_event and OSError)


    def _poison_gateway(self):  # Corrected in previous responses
        # ... (Implementation from previous response - handles stop_event and OSError)


    def _heartbeat(self):  # Corrected in previous response
       # ... (Implementation from previous response - robust heartbeat checks)

    def _extract_packet_data(self, packet):  # Completed version - handles various protocols
        """Extracts relevant data from a given packet."""
        try:
            packet_data = {"Timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}

            if IP in packet:
                # ... (IP layer extraction - same as in testcode.py)
            elif ARP in packet:
                # ... (ARP layer extraction - same as in testcode.py)

            return packet_data  # Always return the dictionary, even if empty
        except Exception as e:
            self._print_error(f"Error extracting packet data: {e}")
            if self.verbose:
                self.console.print_exception()
            return None  # Return None to signal error


    def process_intercepted_packet(self, packet): # Corrected version
        # ... (Implementation from previous response, with robust error handling)


    def _sniff_packets(self): # Corrected version
        # ... (Implementation from previous response - handles stop_event cleanly)



    def _restore(self):  # Corrected in previous responses
        # ... (Implementation from previous response - robust ARP restoration)


    def start(self):  # Corrected in previous responses - full version
        # ... (Complete implementation from previous response - handles Live context, thread management, and error handling correctly)

    def stop(self):  # Corrected in previous responses
        # ... (Implementation from previous response - stops threads gracefully, restores ARP, disables IP forwarding)


    def restore(self):  # No changes needed here
        # ... (Existing correct implementation from testcode.py)



if __name__ == "__main__":
    # ... (argparse and main block - same as corrected testcode.py)


