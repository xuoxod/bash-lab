import socket
import multiprocessing
import logging
import netifaces
import time
from scapy.all import *
from multiprocessing import Queue, Event, Process, Lock, Condition
from typing import Optional
from packetsaver import PacketSaver
from defaultinterfacegetter import DefaultInterfaceGetter
from rich import print
from rich.table import Table
from rich.panel import Panel

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class Sniffer:
    def __init__(
        self,
        interface: Optional[str] = None,
        buffer_size: int = 65536,
        logger: Optional[logging.Logger] = None,
        data_queue: Optional[Queue] = None,
    ):
        self.interface = interface or DefaultInterfaceGetter.get_default_interface()
        self.buffer_size = buffer_size

        if data_queue is not None:  # Use provided queue
            self.data_queue = data_queue
        else:
            self.data_queue: Queue = multiprocessing.Queue()  # Multiprocess queue

        self.stop_event: Event = multiprocessing.Event()
        self.capture_process: Optional[Process] = None
        self.logger = logger or logging.getLogger(__name__)
        self.lock = Lock()  # Use multiprocessing Lock
        self.processing_condition = Condition(
            self.lock
        )  # Condition variable for signaling
        self.packet_saver = PacketSaver()  # Initialize PacketSaver

    def _capture_loop(self):
        try:
            raw_socket = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
            )
            raw_socket.settimeout(1)  # Timeout for responsiveness
            raw_socket.bind((self.interface, 0))

            while not self.stop_event.is_set():
                try:
                    raw_data, _ = raw_socket.recvfrom(self.buffer_size)
                    with self.processing_condition:  # Acquire condition lock
                        self.data_queue.put(raw_data)
                        self.processing_condition.notify()  # Notify processing thread

                except socket.timeout:
                    pass  # Check stop_event on timeout
                except (socket.error, OSError) as se:  # Handle socket errors
                    self.logger.error(f"Socket error in _capture_loop: {se}")
                    break
                except Exception as exc:  # Catch unexpected errors
                    self.logger.exception(f"Unexpected error in _capture_loop: {exc}")
                    break

        finally:  # Ensure socket is closed
            if "raw_socket" in locals() and raw_socket:
                raw_socket.close()

    def start_capture(self):  # Correct start method
        if (
            self.capture_process is None or not self.capture_process.is_alive()
        ):  # Check if already running
            self.capture_process = multiprocessing.Process(
                target=self._capture_loop, daemon=True  # Daemon process
            )
            self.capture_process.start()
        else:
            self.logger.warning("Capture already started.")

    def stop_capture(self):
        if self.capture_process:
            self.stop_event.set()
            self.capture_process.join(timeout=2.0)  # Join with timeout

            if self.capture_process.is_alive():  # Force terminate if necessary
                self.logger.warning("Force-terminating capture process.")
                self.capture_process.terminate()

    def run(self, test_mode=False, save_csv=False, save_json=False):
        self.start_capture()  # Start capturing packets in a separate process

        # --- Create and start the processing process ---
        self.processing_process = multiprocessing.Process(
            target=self.process_packets,
            args=(save_csv, save_json),  # Pass args to the process
            daemon=True,  # Make it a daemon process
        )
        self.processing_process.start()

        try:
            while True:  # Keep the main process alive to handle interrupts
                time.sleep(1)  # Prevent busy waiting
        except KeyboardInterrupt:
            print("Stopping...")
        finally:
            self.stop_capture()
            if self.processing_process:  # Ensure processing process is stopped
                self.stop_event.set()  # Signal termination to the processing loop
                self.processing_condition.acquire()  # Acquire the condition lock
                self.processing_condition.notify()  # Wake up the processing thread if it's waiting
                self.processing_condition.release()  # Release the condition lock
                self.processing_process.join()  # Wait for the processing process to terminate
            self.logger.info("Sniffer stopped.")

    def process_packets(self, save_csv, save_json):  # Takes args directly
        """Processes captured packets from the queue."""
        while not self.stop_event.is_set():
            with self.processing_condition:  # Use the condition for waiting
                self.processing_condition.wait()  # Wait for new packets or stop signal
                while not self.data_queue.empty() and not self.stop_event.is_set():
                    try:
                        raw_packet = self.data_queue.get()
                        packet = Ether(raw_packet)

                        packet_data = self._extract_packet_data(packet)
                        if packet_data is None:
                            continue

                        table = Table(title="Packet Details", show_lines=True)

                        # --- Add columns explicitly ---
                        table.add_column("Layer", style="white", no_wrap=True)

                        # Layer column
                        table.add_column("Field", style="green", no_wrap=True)

                        # Field column
                        table.add_column("Value", style="magenta")

                        for layer_name, field_data in self._group_by_layer(
                            packet_data
                        ).items():
                            for field_name, value in field_data.items():
                                table.add_row(layer_name, field_name, str(value))

                        print(Panel(table, title="Captured Packet"))

                        if save_csv:
                            self.packet_saver.save_packet_data(
                                packet_data, "packet_data.csv"
                            )
                        if save_json:
                            self.packet_saver.save_packet_data(
                                packet_data, "packet_data.json"
                            )

                    except Exception as e:
                        self.logger.error(f"Error processing packet: {e}")

    def _extract_packet_data(self, packet):
        packet_data = {"Timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
        pkt_copy = packet.copy()  # Create a copy

        try:
            # Ethernet Layer
            if Ether in pkt_copy:
                packet_data["Ethernet_Source_MAC"] = pkt_copy[Ether].src
                packet_data["Ethernet_Destination_MAC"] = pkt_copy[Ether].dst
                packet_data["Ethernet_Type"] = pkt_copy[Ether].type  # Get Ethernet type

            # IP Layer
            if IP in pkt_copy:
                packet_data["IP_Source"] = pkt_copy[IP].src
                packet_data["IP_Destination"] = pkt_copy[IP].dst
                packet_data["IP_Version"] = pkt_copy[IP].version
                packet_data["IP_Header_Length"] = pkt_copy[IP].ihl  # IP Header length
                packet_data["IP_Total_Length"] = pkt_copy[IP].len  # Total Packet length
                packet_data["IP_TTL"] = pkt_copy[IP].ttl  # Time To Live

            # TCP Layer
            if TCP in pkt_copy:
                packet_data["TCP_Source_Port"] = pkt_copy[TCP].sport
                packet_data["TCP_Destination_Port"] = pkt_copy[TCP].dport
                # ... extract other TCP fields like flags, sequence number, etc.

            # UDP Layer  (Handle UDP separately, not in an 'else' with TCP)
            if UDP in pkt_copy:
                packet_data["UDP_Source_Port"] = pkt_copy[UDP].sport
                packet_data["UDP_Destination_Port"] = pkt_copy[UDP].dport
                # ... other UDP fields

            # DNS Layer
            if DNS in pkt_copy:
                if DNSQR in pkt_copy:  # Check for DNS Question Record
                    packet_data["DNS_Query"] = pkt_copy[
                        DNSQR
                    ].qname.decode()  # Decode bytes to string
                # ... handle DNS answers (DNSRR) if needed

            # ICMP Layer
            if ICMP in pkt_copy:
                packet_data["ICMP_Type"] = pkt_copy[ICMP].type
                # ... other ICMP fields

            # ARP Layer
            if ARP in pkt_copy:
                packet_data["ARP_Operation"] = pkt_copy[ARP].op
                # ... other ARP fields as needed

            # ... Add handling for other protocols/layers as required ...

        except Exception as e:
            self.logger.error(f"Error dissecting packet: {e}")
            return None  # Indicate failure

        return packet_data

    def _group_by_layer(self, packet_data):
        layered_data = {}
        for key, value in packet_data.items():
            try:
                layer_name, field_name = key.split("_", 1)
            except ValueError:  # Handle keys without underscores (e.g., 'Timestamp')
                layer_name = "General"  # Group these into a "General" category
                field_name = key  # Use the entire key as the field name
            if layer_name not in layered_data:
                layered_data[layer_name] = {}
            layered_data[layer_name][field_name] = value
        return layered_data
