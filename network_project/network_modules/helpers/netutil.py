#!/usr/bin/python3


import os
import getpass
import platform
import netifaces
import logging
import socket
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


import os
import getpass
import platform
import netifaces
import logging
import socket
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
            raise InterfaceError(
                "No valid network interface found."
            )  # More specific exception

    def get_default_interface(self):
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][1]
        except KeyError:
            raise DefaultInterfaceNotFoundError(
                "No default gateway found."
            )  # Raise exception instead of returning None

    def get_own_mac(self):
        try:
            return netifaces.ifaddresses(self.interface)[netifaces.AF_LINK][0]["addr"]
        except (KeyError, IndexError):
            raise InterfaceError(
                f"Could not get MAC address for interface {self.interface}"
            )

    def get_own_ip(self):
        try:
            return netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]["addr"]
        except (KeyError, IndexError):
            raise InterfaceError(
                f"Could not get IP address for interface {self.interface}"
            )

    def get_mac(self, ip_address):
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
                timeout=2,
                verbose=0,
                iface=self.interface,  # Use provided interface if available
            )
            if ans:
                return ans[0][1].hwsrc
            return None  # Or raise an exception for clarity.
        except Exception as e:  # Catch potential Scapy errors
            logger.error(f"Error getting MAC for {ip_address}: {e}")  # Log the error.
            return (
                None  # Return None instead of raising a potentially confusing exception
            )

    def get_ip(self, mac_address):
        try:  # Suggest a try-except
            for (
                iface
            ) in (
                netifaces.interfaces()
            ):  # Changed to interfaces() to get list of network interfaces
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_LINK in addrs:  # Check for AF_LINK
                    if (
                        addrs[netifaces.AF_LINK][0]["addr"] == mac_address
                    ):  # Correctly checking MAC address
                        if netifaces.AF_INET in addrs:  # Corrected AF_INET Key
                            return addrs[netifaces.AF_INET][0][
                                "addr"
                            ]  # Correctly access the addr
            return None  # Return None instead of nothing
        except (KeyError, IndexError):
            return None

    def get_interface(self):
        return self.interface

    def get_gateway_ip(self):
        try:
            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][0]
        except KeyError:
            return None  # Or raise an exception if no default gateway is found.

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

    def get_hostname(ip_address):  # Hostname function

        try:
            return socket.gethostbyaddr(ip_address)[0]  # Reverse DNS lookup
        except socket.herror:  # Handle hostname not found
            return None

    def resolve_hostname(hostname):  # IP address from hostname

        try:
            return socket.gethostbyname(hostname)  # Forward DNS lookup

        except socket.gaierror:  # Handle hostname resolution failure
            return None

    def ping(host, count=4, timeout=2):

        param = (
            "-n" if platform.system().lower() == "windows" else "-c"
        )  # Platform-specific ping command

        command = ["ping", param, str(count), "-W", str(timeout), host]

        try:
            subprocess.check_output(command)  # Run ping command
            return True  # Successful ping

        except subprocess.CalledProcessError:  # Ping failed
            return False


if __name__ == "__main__":
    netutil = NetUtil(interface="wlp0s20f3")  # Specify your interface here
    ip = netutil.get_own_ip()
    print(f"IP address: {ip}")
