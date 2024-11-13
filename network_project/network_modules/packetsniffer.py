import socket
import threading
import queue
import logging  # Import logging here
import netifaces  # Import netifaces
from networkexceptions import (
    SocketCreationError,
    SocketBindingError,
    DefaultInterfaceNotFoundError,
)
from defaultinterfacegetter import DefaultInterfaceGetter


class PacketSniffer:
    """
    Captures raw network data from a specified interface.
    """

    def __init__(self, interface=None, buffer_size=65536, logger=None):
        self.interface = interface or DefaultInterfaceGetter.get_default_interface()
        self.buffer_size = buffer_size
        self.stop_event = threading.Event()
        self.data_queue = queue.Queue()  # Thread-safe queue for data transfer
        self.processing_condition = threading.Condition()  # Add the condition here
        self.logger = logger or logging.getLogger(__name__)

    def _capture_loop(self):
        """
        Internal loop to capture raw data.
        """
        raw_socket = None  # Initialize raw_socket
        try:
            # Create a raw socket
            raw_socket = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
            )
            # Bind the socket to the specified interface
            raw_socket.bind((self.interface, 0))

            while not self.stop_event.is_set():
                # Receive raw data
                raw_data, _ = raw_socket.recvfrom(self.buffer_size)
                with self.processing_condition:  # Acquire the condition
                    self.data_queue.put(raw_data)  # Put data into the queue
                    self.processing_condition.notify()  # Notify the condition

        except socket.error as se:
            self.logger.error(f"Socket error in _capture_loop: {se}")
            raise SocketCreationError(f"Failed to create raw socket: {se}") from se
        except SocketBindingError as sbe:
            self.logger.error(f"Socket binding error in _capture_loop: {sbe}")
            raise SocketBindingError(f"Failed to bind the raw socket: {sbe}") from sbe
        except Exception as exc:
            self.logger.error(f"Unexpected error in _capture_loop: {exc}")
            raise Exception(f"General error in _capture_loop: {exc}") from exc
        finally:
            if raw_socket:
                raw_socket.close()

    def start_capture(self):
        """
        Starts the data capture thread.
        """
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()

    def stop_capture(self):
        """
        Stops the data capture thread.
        """
        self.stop_event.set()
        if self.thread:
            self.thread.join()

    # Removed the get_data() method
