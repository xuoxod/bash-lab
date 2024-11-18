#!/usr/bin/python3
import multiprocessing
import time
import logging
import argparse
from sniffer import Sniffer as PacketSniffer  # Use the new Sniffer class
from defaultinterfacegetter import DefaultInterfaceGetter

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class PacketMaster:
    def __init__(
        self, interface=None, test_mode=False, save_csv=False, save_json=False
    ):
        self.interface = interface or DefaultInterfaceGetter.get_default_interface()
        self.test_mode = test_mode
        self.save_csv = save_csv
        self.save_json = save_json
        self.logger = logging.getLogger(__name__)
        self.data_getter = PacketSniffer(
            interface=self.interface, logger=self.logger
        )  # Initialize Sniffer
        self.capture_process = None  # updated code

    def run_(self):
        self._parse_arguments()  # Parse arguments first

        self.capture_process = multiprocessing.Process(
            target=self.data_getter.run,
            kwargs={
                "test_mode": self.test_mode,
                "save_csv": self.save_csv,
                "save_json": self.save_json,
            },
        )
        self.capture_process.start()

        try:
            self.capture_process.join()  # Wait for the capture process to finish
        except KeyboardInterrupt:
            print("Stopping...")
            self.stop()

    def run(self):
        self._parse_arguments()

        self.capture_process = multiprocessing.Process(
            target=self.data_getter.run,  # Call run
            kwargs={
                "test_mode": self.test_mode,
                "save_csv": self.save_csv,
                "save_json": self.save_json,
            },
        )

        self.capture_process.start()  # Start the sniffer's run_1 method in a separate process
        self.logger.info("Sniffer process started.")

        try:
            while (
                True
            ):  # Main loop to keep packetmaster alive and handle keyboard interrupt
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Stopping PacketMaster...")
            self.stop_1()  # Call stop method to stop the sniffer

    def stop_(self):
        if (
            self.capture_process and self.capture_process.is_alive()
        ):  # Check if process is running
            self.data_getter.stop_event.set()  # Signal the sniffer to stop
            self.capture_process.join(timeout=2.0)  # give time to clean up
            if self.capture_process.is_alive():  # updated code
                self.logger.warning("Forcefully terminating capture process.")
                self.capture_process.terminate()  # updated code
        print("Packet Master stopped.")

    def stop_2(self):
        if self.capture_process and self.capture_process.is_alive():
            self.data_getter.stop()  # Call the Sniffer's stop() method
            self.capture_process.join(timeout=2.0)  # Wait for process to stop

            if (
                self.capture_process.is_alive()
            ):  # Forceful termination only if necessary
                self.capture_process.terminate()
                self.logger.warning("Sniffer process force-terminated.")

        self.logger.info("Packet Master stopped.")

    def stop_1(self):  # quick_stop
        if self.capture_process.is_alive():  # Check if still running
            self.data_getter.stop(
                quick_stop=True  # Important: tell Sniffer to do a quick stop
            )
            self.capture_process.join(timeout=2.0)  # Allow short time to finish

            if self.capture_process.is_alive():  # Terminate if it hasn't stopped yet
                self.capture_process.terminate()  # Forceful shutdown
        self.logger.info("Packet Master stopped.")  # Consistent logging message

    def stop(
        self,
    ):  # detailed stop (almost the same as stop_1 but uses quick_stop=False)
        if self.capture_process.is_alive():  # Check if its still running
            self.data_getter.stop(quick_stop=False)  # Allow detailed stop
            self.capture_process.join(
                timeout=5.0
            )  # Longer timeout to allow full shutdown
            if (
                self.capture_process.is_alive()
            ):  # Terminate if it hasn't stopped after timeout
                self.capture_process.terminate()
        self.logger.info("Packet Master stopped.")  # Consistent logging message

    def _parse_arguments(self):  # updated code
        """Parses command-line arguments."""
        parser = argparse.ArgumentParser(
            description="Network packet monitor and saver."
        )
        parser.add_argument("-i", "--interface", help="Interface to capture from")
        parser.add_argument(
            "-t", "--test", action="store_true", help="Run in test mode"
        )
        parser.add_argument("--save-csv", action="store_true", help="Save data to CSV")
        parser.add_argument(
            "--save-json", action="store_true", help="Save data to JSON"
        )
        args = parser.parse_args()

        if args.interface:
            self.interface = args.interface
        self.test_mode = args.test
        self.save_csv = args.save_csv
        self.save_json = args.save_json


if __name__ == "__main__":
    monitor = PacketMaster()
    monitor.run()
