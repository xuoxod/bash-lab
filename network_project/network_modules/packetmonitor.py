#!/usr/bin/python3
import queue
import threading
import time
import logging
import argparse

from scapy.all import *  # Import Scapy for packet parsing
from rich import print
from rich.table import Table
from rich.panel import Panel

from packetsniffer import PacketSniffer
from networkexceptions import (
    NetworkSnifferError,
    SocketCreationError,
    SocketBindingError,
)
from defaultinterfacegetter import DefaultInterfaceGetter
from packetsaver import PacketSaver

# Configure logging (adjust level and format as needed)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class PacketMonitor:
    def __init__(self, interface="wlp0s20f3", test_mode=False):
        self.interface = interface or DefaultInterfaceGetter.get_default_interface()
        self.test_mode = test_mode
        self.save_csv = False
        self.save_json = False
        self.logger = logging.getLogger(__name__)
        self.packet_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.data_getter = PacketSniffer(interface=self.interface)
        self.processing_condition = self.data_getter.processing_condition
        self.packet_saver = PacketSaver()

    def _capture_packets(self):
        if self.test_mode:
            # Sample packet data (replace with your actual test data)
            sample_packets = [
                b"\x00\x15\x5d\x01\x02\x1c\x00\x0c\x29\x96\x8f\x9b\x08\x00\x45\x00\x00\x3c\x4c\x9b\x40\x00\x40\x06\x7c\x9c\xc0\xa8\x01\x65\xac\x1f\x02\xd1\x04\x03\x08\x0a\x02\x9e\x73\x9d\x00\x00\x00\x00\x70\x02\xfa\xf0\xb1\x10\x00\x00\x00\x00\x00\x00\x00\x00",
                # ... more sample packets ...
            ]
            for packet in sample_packets:
                self.data_getter.data_queue.put(packet)
                time.sleep(1)  # Simulate packet arrival
        else:
            try:
                self.data_getter.start_capture()

                # Wait for the processing thread to finish before stopping capture
                with self.processing_condition:
                    while not self.stop_event.is_set():  # Check stop_event periodically
                        try:
                            self.processing_condition.wait(
                                timeout=1
                            )  # Wait with a timeout
                        except KeyboardInterrupt:
                            self.print_status("Interrupt received in capture thread.")
                            self.stop_event.set()  # Signal the thread to stop

            except SocketCreationError as e:
                self.logger.critical(f"Critical error: {e}")
            except SocketBindingError as e:
                self.logger.error(f"Error binding socket: {e}")
            except NetworkSnifferError as e:
                self.logger.error(f"Error in network sniffer: {e}")
            except Exception as e:
                self.logger.exception(f"Unexpected error in _capture_packets: {e}")
            finally:
                self.data_getter.stop_capture()

    def _parse_arguments(self):
        """Parses command-line arguments with detailed help."""
        parser = argparse.ArgumentParser(
            description="""Network Packet Monitor: A tool to capture, analyze,
            and optionally save network packets from a specified interface.""",
            epilog="""Examples:
                # Capture packets on eth0 and save to CSV:
                ./packetmonitor.py -i eth0 --save-csv

                # Capture packets on wlan0 and save to JSON:
                ./packetmonitor.py -i wlan0 --save-json

                # Run in test mode (prints sample packets):
                ./packetmonitor.py -t
            """,
            formatter_class=argparse.RawDescriptionHelpFormatter,  # Preserve formatting
        )
        parser.add_argument(
            "-i",
            "--interface",
            default="eth0",
            help="Network interface to monitor (default: eth0). Example: eth0, wlan0",
        )
        parser.add_argument(
            "--save-csv",
            action="store_true",
            help="Save captured packet data to a CSV file named 'packet_data.csv'.",
        )
        parser.add_argument(
            "--save-json",
            action="store_true",
            help="Save captured packet data to a JSON file named 'packet_data.json'.",
        )
        parser.add_argument(
            "-t",
            "--test",
            action="store_true",
            help="Run in test mode. Instead of live capture, prints sample packet data.",
        )
        args = parser.parse_args()
        self.interface = args.interface
        self.save_csv = args.save_csv
        self.save_json = args.save_json
        self.test_mode = args.test

    def _extract_packet_data(self, packet):
        """Extracts relevant data from a parsed Scapy packet."""
        packet_data = {}

        try:
            packet_data["Timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
            packet_data["Ethernet_Source_MAC"] = packet.src
            packet_data["Ethernet_Destination_MAC"] = packet.dst
            packet_data["Ethernet_Type"] = str(packet.type)

            if "IP" in packet:
                packet_data["IP_Source"] = packet[IP].src
                packet_data["IP_Destination"] = packet[IP].dst
                packet_data["IP_Protocol"] = str(packet[IP].proto)

                try:
                    packet_data["Source_Hostname"] = socket.gethostbyaddr(
                        packet[IP].src
                    )[0]
                except socket.herror:
                    packet_data["Source_Hostname"] = "Unknown"

                try:
                    packet_data["Destination_Hostname"] = socket.gethostbyaddr(
                        packet[IP].dst
                    )[0]
                except socket.herror:
                    packet_data["Destination_Hostname"] = "Unknown"

            if "ICMP" in packet:
                packet_data["ICMP_Type"] = str(packet[ICMP].type)
                packet_data["ICMP_Code"] = str(packet[ICMP].code)
                packet_data["ICMP_ID"] = str(packet[ICMP].id)
                packet_data["ICMP_Sequence"] = str(packet[ICMP].seq)

            if "DNS" in packet:
                packet_data["DNS_Query"] = str(packet[DNS].qd.qname.decode())
                if packet[DNS].an:
                    packet_data["DNS_Answer"] = str(packet[DNS].an.rdata)

            if "ARP" in packet:
                packet_data["ARP_Operation"] = str(packet[ARP].op)
                packet_data["ARP_Sender_IP"] = str(packet[ARP].psrc)
                packet_data["ARP_Sender_MAC"] = str(packet[ARP].hwsrc)
                packet_data["ARP_Target_IP"] = str(packet[ARP].pdst)
                packet_data["ARP_Target_MAC"] = str(packet[ARP].hwdst)

            if "TCP" in packet:
                packet_data["TCP_Source_Port"] = str(packet[TCP].sport)
                packet_data["TCP_Destination_Port"] = str(packet[TCP].dport)
            elif "UDP" in packet:
                packet_data["UDP_Source_Port"] = str(packet[UDP].sport)
                packet_data["UDP_Destination_Port"] = str(packet[UDP].dport)

            # Add more layers and fields as needed

        except Exception as e:
            logging.error(f"Error extracting packet data: {e}")

        return packet_data

    def _process_packets(self):
        while not self.stop_event.is_set():
            with self.processing_condition:
                self.processing_condition.wait()  # Wait for notification

                while not self.data_getter.data_queue.empty():
                    raw_packet = self.data_getter.data_queue.get()

                    try:
                        # Parse the packet using Scapy
                        packet = Ether(raw_packet)

                        # --- Pretty Print with Rich ---
                        table = Table(title="Packet Details")
                        table.add_column("Field", style="cyan", no_wrap=True)
                        table.add_column("Value", style="magenta")

                        # Add common layers (customize as needed)
                        table.add_row("Time", time.strftime("%Y-%m-%d %H:%M:%S"))
                        table.add_row("Ethernet Source MAC", packet.src)
                        table.add_row("Ethernet Destination MAC", packet.dst)
                        table.add_row("Ethernet Type", str(packet.type))

                        if "IP" in packet:
                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst

                            try:
                                src_hostname = socket.gethostbyaddr(src_ip)[0]
                            except socket.herror:
                                src_hostname = "Unknown"

                            try:
                                dst_hostname = socket.gethostbyaddr(dst_ip)[0]
                            except socket.herror:
                                dst_hostname = "Unknown"

                            table.add_row("IP Source", src_ip)
                            table.add_row("Source Hostname", src_hostname)
                            table.add_row("IP Destination", dst_ip)
                            table.add_row("Destination Hostname", dst_hostname)
                            table.add_row("IP Protocol", str(packet[IP].proto))

                        if "ICMP" in packet:
                            table.add_row("ICMP Type", str(packet[ICMP].type))
                            table.add_row("ICMP Code", str(packet[ICMP].code))
                            table.add_row("ICMP ID", str(packet[ICMP].id))
                            table.add_row("ICMP Sequence", str(packet[ICMP].seq))

                        if "DNS" in packet:
                            table.add_row(
                                "DNS Query", str(packet[DNS].qd.qname.decode())
                            )
                            if packet[DNS].an:
                                table.add_row("DNS Answer", str(packet[DNS].an.rdata))

                        if "ARP" in packet:
                            table.add_row("ARP Operation", str(packet[ARP].op))
                            table.add_row("ARP Sender IP", str(packet[ARP].psrc))
                            table.add_row("ARP Sender MAC", str(packet[ARP].hwsrc))
                            table.add_row("ARP Target IP", str(packet[ARP].pdst))
                            table.add_row("ARP Target MAC", str(packet[ARP].hwdst))

                        if "TCP" in packet:
                            table.add_row("TCP Source Port", str(packet[TCP].sport))
                            table.add_row(
                                "TCP Destination Port", str(packet[TCP].dport)
                            )
                        elif "UDP" in packet:
                            table.add_row("UDP Source Port", str(packet[UDP].sport))
                            table.add_row(
                                "UDP Destination Port", str(packet[UDP].dport)
                            )

                        # Add more layers and fields as needed

                        # Print the formatted table
                        print(
                            Panel(table, title=f"Captured Packet From {dst_hostname}")
                        )

                        # --- Save Packet Data (if enabled) ---
                        if self.save_csv:
                            print("Saving packet data to CSV...")
                            packet_data = self._extract_packet_data(packet)
                            self.packet_saver.save_packet_data(
                                packet_data, "packet_data.csv"
                            )
                        if self.save_json:
                            print("Saving packet data to JSON...")
                            packet_data = self._extract_packet_data(packet)
                            self.packet_saver.save_packet_data(
                                packet_data, "packet_data.json"
                            )

                    except Exception as e:
                        logging.error(f"Error processing packet: {e}")

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

    def run(self):
        """Main execution method."""
        self._parse_arguments()
        self.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Stopping...")
            self.stop()


if __name__ == "__main__":
    monitor = PacketMonitor()
    monitor.run()
