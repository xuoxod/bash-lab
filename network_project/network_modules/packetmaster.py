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

    def run(self):
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

    def stop(self):
        if (
            self.capture_process and self.capture_process.is_alive()
        ):  # Check if process is running
            self.data_getter.stop_event.set()  # Signal the sniffer to stop
            self.capture_process.join(timeout=2.0)  # give time to clean up
            if self.capture_process.is_alive():  # updated code
                self.logger.warning("Forcefully terminating capture process.")
                self.capture_process.terminate()  # updated code
        print("Packet Master stopped.")

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
