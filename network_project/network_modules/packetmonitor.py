#!/usr/bin/python3

import socket
import queue
import threading
import time
import logging
from scapy.all import *
from rich import print
from rich.table import Table
from rich.panel import Panel
from network_modules.networksniffer import RawSocketDataGetter
from network_modules.textcolors import TextColors
from networkexceptions import (
    NetworkSnifferError,
    SocketCreationError,
    SocketBindingError,
)

# Configure logging (adjust level and format as needed)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class PacketMonitor:
    def __init__(self, interface="eth0"):
        self.interface = interface
        self.packet_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.data_getter = RawSocketDataGetter(interface=self.interface)
        self.processing_condition = (
            self.data_getter.processing_condition
        )  # Use the condition from data_getter

    def _capture_packets(self):
        try:
            self.data_getter.start_capture()
        except SocketCreationError as e:
            self.logger.critical(f"Critical error: {e}")
            # Handle critical error (e.g., terminate the application)
        except SocketBindingError as e:
            self.logger.error(f"Error binding socket: {e}")
            # Handle the error (e.g., try a different interface)
        except NetworkSnifferError as e:
            self.logger.error(f"Error in network sniffer: {e}")
            # Handle other sniffer errors
        except Exception as e:
            self.logger.exception(f"Unexpected error in _capture_packets: {e}")
            # Handle unexpected errors (log the traceback)
        finally:
            self.data_getter.stop_capture()  # Ensure capture thread is stopped

    def _process_packets(self):
        while not self.stop_event.is_set():
            with self.processing_condition:  # Acquire the condition
                self.processing_condition.wait()  # Wait for notification

                # Directly get data from data_getter's queue
                while not self.data_getter.data_queue.empty():
                    raw_packet = self.data_getter.data_queue.get()
                    # ... (Use Scapy to parse raw_packet and extract metadata)
                    # ... (Pretty print the packet information using rich)

    def start(self):
        self.capture_thread = threading.Thread(
            target=self._capture_packets, daemon=True
        )
        self.processing_thread = threading.Thread(
            target=self._process_packets, daemon=True
        )
        self.capture_thread.start()
        self.processing_thread.start()

    def stop(self):
        self.stop_event.set()
        self.data_getter.stop_capture()
        self.capture_thread.join()
        self.processing_thread.join()
        print("Packet Monitor stopped.")


if __name__ == "__main__":
    monitor = PacketMonitor()
    monitor.start()

    try:
        while True:
            time.sleep(1)  # Keep the main thread alive
    except KeyboardInterrupt:
        print("Stopping...")
        monitor.stop()
