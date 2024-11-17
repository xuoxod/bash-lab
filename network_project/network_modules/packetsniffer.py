import socket
import multiprocessing
import queue
import logging
import netifaces
from networkexceptions import (
    SocketCreationError,
    SocketBindingError,
    DefaultInterfaceNotFoundError,
)
from defaultinterfacegetter import DefaultInterfaceGetter

# For type hinting
from multiprocessing import Queue, Event, Process, Lock
from typing import Optional


class PacketSniffer:

    def __init__(  # updated code
        self,
        interface: Optional[str] = None,
        buffer_size: int = 65536,
        logger: Optional[logging.Logger] = None,
        data_queue: Optional[Queue] = None,  # Accept queue as argument
    ):
        self.interface = interface or DefaultInterfaceGetter.get_default_interface()
        self.buffer_size = buffer_size

        if data_queue is not None:  # Use provided queue or create a new one
            self.data_queue = data_queue
        else:
            self.data_queue: Queue = multiprocessing.Queue()

        self.stop_event: Event = multiprocessing.Event()
        self.capture_process: Optional[Process] = None
        self.logger = logger or logging.getLogger(__name__)
        self.lock = Lock()  # Use multiprocess Lock
        self.processing_condition = multiprocessing.Condition()  # Condition variable

    def _capture_loop(
        self, data_queue: Queue, stop_event: Event
    ):  # updated code, removed queue instantiation
        try:
            raw_socket = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
            )

            raw_socket.settimeout(1)  # timeout to check stop_event more frequently
            raw_socket.bind((self.interface, 0))
            while not stop_event.is_set():
                try:
                    raw_data, _ = raw_socket.recvfrom(self.buffer_size)
                    with self.processing_condition:
                        data_queue.put(raw_data)  # Put data into the queue
                        self.processing_condition.notify()  # Notify waiting threads

                except socket.timeout:  # check stop_event
                    pass  # Check stop_event on timeout
                except (
                    socket.error,
                    OSError,  # Include OSError for potential socket issues
                ) as se:
                    self.logger.error(f"Socket error in _capture_loop: {se}")
                    break  # Exit loop on socket error
                except Exception as exc:  # check for unexpected errors
                    self.logger.exception(f"Unexpected error in _capture_loop: {exc}")
                    break
        finally:  # ensure socket release
            if "raw_socket" in locals() and raw_socket:
                raw_socket.close()

    def start_capture(self):  # updated code
        if (
            self.capture_process is None or not self.capture_process.is_alive()
        ):  # Start only if the process is dead or None
            self.capture_process = multiprocessing.Process(
                target=self._capture_loop,
                args=(self.data_queue, self.stop_event),  # Pass the queue and event
                daemon=True,
            )
            self.capture_process.start()
        else:  # the process has already been started
            print("Capture is already started.")
            self.logger.warning(
                "Attempting to start capture when capture process is already active."
            )

    def start_capture(self):
        self.capture_process = multiprocessing.Process(
            target=self._capture_loop,
            args=(self.data_queue, self.stop_event),
            daemon=True,  # Make process a daemon to exit with main process
        )
        self.capture_process.start()

    def stop_capture(self):
        if self.capture_process:
            self.stop_event.set()
            self.capture_process.join(
                timeout=2.0
            )  # Timeout to avoid indefinite blocking

            if self.capture_process.is_alive():
                self.logger.warning("Force-terminating capture process.")
                self.capture_process.terminate()  # Terminate if still running
