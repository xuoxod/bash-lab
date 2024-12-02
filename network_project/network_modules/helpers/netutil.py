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

from scapy.all import *  #  Import all of Scapy
from scapy.all import IP, Ether, ARP, UDP, TCP, ICMP
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from textcolors import TextColors
from queue import Queue, Empty
from networkexceptions import *

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class NetUtil:
    def __init__(self, interface=None):
        self.interface = interface or self.get_default_interface()
        if not self.interface:
            raise ValueError("No valid network interface found.")

    def get_default_interface(self):
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][1]
        except KeyError:
            return None  # Or handle appropriately, e.g., raise an exception

    def get_own_mac(self):
        try:
            return netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]["addr"]
        except (KeyError, IndexError):
            return None

    def get_own_ip(self):
        try:
            return netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]["addr"]
        except (KeyError, IndexError):
            return None

    def get_mac(self, ip_address):
        try:
            ans, _ = scapy.srp(
                scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_address),
                timeout=2,
                verbose=0,
            )
            if ans:
                return ans[0][1].hwsrc
            return None
        except Exception as e:  # Catch potential Scapy errors
            # Handle the exception (e.g., logging, re-raising)
            return None

    def get_ip(self, mac_address):
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_LINK in addrs:
                    if addrs[netifaces.AF_LINK][0]["addr"] == mac_address:
                        if netifaces.AF_INET in addrs:
                            return addrs[netifaces.AF_INET][0]["addr"]

        except (KeyError, IndexError):
            return None

    def get_interface(self):
        return self.interface

    def get_gateway_ip(self):
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][0]
        except KeyError:
            return None

    def check_root():
        """Checks if the script is running with root privileges."""
        return os.geteuid() == 0

    def request_root():
        """Prompts the user to run the script with root privileges."""
        response = input(
            "This script requires root privileges. Run with sudo? (yes/no): "
        ).lower()
        if response == "yes":
            try:
                os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
            except Exception as e:
                logging.error(f"Error escalating to root: {e}")
                print(f"Error escalating to root: {e}")
                sys.exit(1)
        else:
            print("Root privileges are required. Exiting.")
            sys.exit(1)
