#!/usr/bin/python3
import queue
import threading
import time
import logging
import argparse
import socket
import json
import csv

# trunk-ignore(ruff/F403)
from scapy.all import *  # Import Scapy for packet parsing
from rich import print
from rich.table import Table
from rich.panel import Panel

from packetsniffer import PacketSniffer  # Assuming this is your custom sniffer
from networkexceptions import (
    NetworkSnifferError,
    SocketCreationError,
    SocketBindingError,
)
from defaultinterfacegetter import DefaultInterfaceGetter  # Assuming this is your custom interface getter


# Configure logging (adjust level and format as needed)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class PacketMaster:
    def __init__(self, interface=None, test_mode=False, queue_size=1000):
        self.interface = interface or DefaultInterfaceGetter.get_default_interface()
        self.test_mode = test_mode
        self.save_csv = False
        self.save_json = False
        self.logger = logging.getLogger(__name__)
        # Use a bounded queue to prevent blocking
        self.packet_queue = queue.Queue(maxsize=queue_size)
        self.stop_event = threading.Event()
        self.data_getter = PacketSniffer(interface=self.interface, queue=self.packet_queue)
        self.processing_condition = self.data_getter.processing_condition


    def _capture_packets(self):
        if self.test_mode:
            # Sample packet data (replace with your actual test data)
            sample_packets = [
                b"\x00\x15\x5d\x01\x02\x1c\x00\x0c\x29\x96\x8f\x9b\x08\x00\x45\x00\x00\x3c\x4c\x9b\x40\x00\x40\x06\x7c\x9c\xc0\xa8\x01\x65\xac\x1f\x02\xd1\x04\x03\x08\x0a\x02\x9e\x73\x9d\x00\x00\x00\x00\x70\x02\xfa\xf0\xb1\x10\x00\x00\x00\x00\x00\x00\x00\x00",
                # ... more sample packets ...
            ]
            for packet in sample_packets:
                self.packet_queue.put(packet)
                time.sleep(1)  # Simulate packet arrival
        else:
            try:
                self.data_getter.start_capture()
                # Wait for the processing thread to finish before stopping capture
                with self.processing_condition:
                    while not self.stop_event.is_set():
                        try:
                            self.processing_condition.wait(timeout=1)
                        except KeyboardInterrupt:
                            self.logger.info("Interrupt received in capture thread.")
                            self.stop_event.set()

            except SocketCreationError as e:
                self.logger.critical(f"Critical error creating socket: {e}")
            except SocketBindingError as e:
                self.logger.error(f"Error binding socket: {e}")
            except NetworkSnifferError as e:
                self.logger.error(f"Error in network sniffer: {e}")
            except Exception as e:
                self.logger.exception(f"Unexpected error in _capture_packets: {e}")
            finally:
                self.data_getter.stop_capture()

    def _parse_arguments(self):
        # ... (argument parsing remains the same) ...

    def _extract_packet_data(self, packet):
        """Extracts relevant data from a parsed Scapy packet."""
        packet_data = {"Timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}

        try:
            #Using Scapy's layer iteration for robustness
            for layer in packet.layers():
                layer_name = layer.name
                for field_name, field_value in layer.fields.items():
                    packet_data[f"{layer_name}_{field_name}"] = str(field_value)
                    # Handle specific data types as needed (e.g., decode bytes)

        except Exception as e:
            logging.error(f"Error extracting packet data: {e}")

        return packet_data

    def _process_packets(self):
        while not self.stop_event.is_set():
            with self.processing_condition:
                try:
                    while not self.packet_queue.empty():
                        raw_packet = self.packet_queue.get()
                        self._process_single_packet(raw_packet)
                        self.packet_queue.task_done() #Mark task as complete
                except queue.Empty:
                    pass #Handle empty queue gracefully


    def _process_single_packet(self, raw_packet):
        try:
            packet = Ether(raw_packet)
            packet_data = self._extract_packet_data(packet)

            # Rich Table (Simplified for better readability)
            table = Table(title="Packet Details")
            table.add_column("Field", style="cyan", no_wrap=True)
            table.add_column("Value", style="magenta")

            for field, value in packet_data.items():
                table.add_row(field, value)

            print(Panel(table, title=f"Captured Packet From {self.interface}"))


            # CSV/JSON saving (Improved efficiency)
            if self.save_csv:
                self._save_to_csv(packet_data, "packet_data.csv")
            if self.save_json:
                self._save_to_json(packet_data, "packet_data.json")

        except Exception as e:
            logging.error(f"Error processing packet: {e}")


    def _save_to_csv(self, packet_data, filename):
      try:
          with open(filename, 'a', newline='', encoding='utf-8') as csvfile:
              fieldnames = packet_data.keys()
              writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
              if csvfile.tell() == 0: #check if file is empty
                  writer.writeheader()
              writer.writerow(packet_data)
      except Exception as e:
          logging.error(f"Error saving to CSV: {e}")

    def _save_to_json(self, packet_data, filename):
      try:
          with open(filename, 'a', encoding='utf-8') as jsonfile:
              json.dump(packet_data, jsonfile, indent=4)
              jsonfile.write('\n') #Add newline for multiple packets
      except Exception as e:
          logging.error(f"Error saving to JSON: {e}")



    def start(self):
        self.capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
        self.processing_thread = threading.Thread(target=self._process_packets, daemon=True)
        self.capture_thread.start()
        self.processing_thread.start()

    def stop(self):
        self.stop_event.set()
        self.data_getter.stop_capture()
        self.capture_thread.join()
        self.processing_thread.join()
        print("Packet Monitor stopped.")
        self.packet_queue.join() #wait for queue to empty

    def run(self):
        self._parse_arguments()
        self.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping...")
            self.stop()


if __name__ == "__main__":
    monitor = PacketMaster()
    monitor.run()
