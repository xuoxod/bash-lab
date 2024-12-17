#!/usr/bin/python3

import logging
import time
from queue import Queue, Empty
from rich.console import Console
from rich.table import Table
from rich.live import Live

from scapy.all import *
from scapy.layers.bluetooth import *  # Import Bluetooth layers
from scapy.layers.bluetooth4LE import *  # Import all BTLE layers

# Assuming these are defined elsewhere in your project
from helpers.netutil import NetUtil
from networkexceptions import BluetoothSocketError

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class BluetoothScanner:
    def __init__(self, interface=None):
        self.interface = (
            interface or NetUtil().get_default_interface()
        )  # Provide backup interface
        self.console = Console()
        self.found_devices = {}  # Dictionary to store found devices
        self.packet_queue = Queue()

    def sniff_bluetooth_packets(self, timeout=10):
        """Sniffs Bluetooth packets and adds them to a queue."""
        try:

            sniff(
                prn=self.packet_handler,
                timeout=timeout,
                iface=self.interface,  # Use correct interface from conf
                store=False,  # Important for performance
                filter="bluetooth",  # Filter for efficiency
            )
        except Exception as e:
            self.logger.error(f"Error during sniffing: {e}")

    def packet_handler(self, pkt):
        """Handles sniffed Bluetooth packets, extracting device information."""
        if pkt.haslayer(HCI_LE_Meta_Advertising_Report):  # Check correct layer
            addr = pkt[HCI_LE_Meta_Advertising_Report].addr
            name = "Unknown"
            if pkt.haslayer(EIR_CompleteLocalName):
                name = pkt[EIR_CompleteLocalName].local_name.decode()
            elif pkt.haslayer(EIR_ShortenedLocalName):
                name = pkt[EIR_ShortenedLocalName].local_name.decode()
            rssi = pkt[HCI_LE_Meta_Advertising_Report].rssi

            if addr not in self.found_devices:  # Avoid duplicates
                self.found_devices[addr] = {
                    "name": name,
                    "rssi": rssi,
                }  # Store in dictionary
                self.packet_queue.put(self.found_devices[addr])  # Add to queue

    def display_devices(self, timeout=10):
        """Displays Bluetooth devices in a live table using Rich."""
        sniff_thread = threading.Thread(
            target=self.sniff_bluetooth_packets,
            daemon=True,
            kwargs={"timeout": timeout},  # daemon important for safe termination
        )  # daemon=True for safety
        sniff_thread.start()  # Start sniffing thread

        with Live(
            Table(title="Bluetooth Devices", style="bold magenta"), refresh_per_second=4
        ) as live_table:
            live_table.table.add_column("Address", justify="left", style="cyan")
            live_table.table.add_column("Name", justify="left", style="green")
            live_table.table.add_column("RSSI", justify="right", style="yellow")

            try:
                start_time = time.time()
                while time.time() - start_time < timeout:
                    try:
                        device = self.packet_queue.get(
                            timeout=0.1
                        )  # timeout necessary to avoid blocking
                        live_table.table.add_row(
                            device, device.name, str(device.rssi)
                        )  # Add to table
                    except Empty:
                        pass
            except KeyboardInterrupt:
                logger.info("Scanning stopped by user.")
            finally:  # Ensure clean stop
                sniff_thread.join(timeout=0.5)  # Wait for thread with safety net


class BluetoothConnector:
    def __init__(self, target_address):
        self.target_address = target_address
        self.socket = None

    def connect(self, channel=1):  # RFCOMM channel 1
        """Connects to a Bluetooth device using L2CAP."""
        if self.socket:
            self.disconnect()  # Disconnect current socket if it's open

        try:
            self.socket = BluetoothL2CAPSocket(
                self.target_address
            )  # Correct socket type
            self.console.print(
                f"[bold green]Connected to {self.target_address} on channel {channel}[/]"
            )
        except BluetoothSocketError as e:
            self.console.print(f"[bold red]Connection failed: {e}[/]")
            self.socket = None  # Reset the socket in case of failure

    def disconnect(self):
        if self.socket:
            self.socket.close()
            self.socket = None
            self.console.print(
                f"[bold yellow]Disconnected from {self.target_address}[/]"
            )

    def send(self, data):  # Now accepts data to send
        """Sends data to the connected device."""
        if not self.socket:  # Corrected check here for self.socket
            self.console.print("[bold red]Not connected.[/]")
            return

        try:  # Handle exceptions during send
            self.socket.send(raw(data))
            self.console.print(f"[bold green]Sent: {data}[/]")
        except Exception as e:
            self.console.print(f"[bold red]Send failed: {e}[/]")
            self.disconnect()

    def receive(self, size=1024):
        """Receives data from the connected device."""
        if not self.socket:
            self.console.print("[bold red]Not connected.[/]")
            return None
        try:
            data = self.socket.recv(size)
            if data:  # Check if data is not empty
                self.console.print(
                    f"[bold green]Received: {data}[/]"
                )  # Print the received data
                return data
        except Exception as e:  # Handles exceptions during receiving
            self.console.print(f"[bold red]Receive failed: {e}[/]")
            self.disconnect()  # Handle error by closing the socket
            return None


if __name__ == "__main__":
    console = Console()

    try:
        scanner = BluetoothScanner()  # Default interface

        console.print("[bold blue]Scanning for Bluetooth devices...[/]")
        scanner.display_devices(timeout=5)  # 5 second scan

        if scanner.found_devices:
            console.print("[bold blue]Found devices:[/]")
            for address, info in scanner.found_devices.items():  # Corrected here
                console.print(
                    f"  {address} - {info['name']} ({info['rssi']})"  # Correctly displaying address
                )  # Added indentation for better readability
            target_address = console.input(
                "[bold blue]Enter the address of the device to connect to: [/]"
            )

            connector = BluetoothConnector(target_address)
            connector.connect()

            if connector.socket:
                while True:
                    try:
                        message = input("Enter message to send (or 'exit'): ")
                        if message.lower() == "exit":
                            break
                        connector.send(message.encode())  # Send encoded message
                        response = connector.receive()
                        if response:
                            print(
                                response.load.decode()
                            )  # Decode response if available
                    except KeyboardInterrupt:  # Add Ctrl+C handling
                        print("Exiting...")
                        break
                connector.disconnect()

        else:
            console.print("[bold yellow]No Bluetooth devices found.[/]")

    except BluetoothSocketError as e:  # Handle any other potential errors during init.
        console.print(f"[bold red]Error: {e}")
    except Exception as e:  # Handle other exceptions that may cause issues.
        console.print(f"[bold red]An unexpected error occurred: {e}")
