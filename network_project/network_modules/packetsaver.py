#!/usr/bin/python3

import threading
import subprocess
import time
import os
import netifaces
import errno
import json  # Add JSON import
import csv
from scapy.all import *
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel  # Import Panel
from rich.text import Text


class PacketSaver:
    """Saves packet data to CSV and JSON files."""

    def _create_csv(self, filename, fieldnames):
        """Creates a new CSV file with headers."""
        with open(filename, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

    def save_to_csv(self, data, filename):
        """Appends packet data to a CSV file."""
        try:

            fieldnames = (
                data.keys()
            )  # Dynamically getting them from the packet_data dict

            if not os.path.exists(filename):
                self._create_csv(
                    filename, fieldnames
                )  # Ensure header row if file doesn't exist

            with open(filename, "a", newline="") as csvfile:  # "a" to append
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writerow(data)  # Write the data to the CSV

        except Exception as e:
            print(f"Error saving to CSV: {e}")

    def save_to_json(self, data, filename):
        """Appends packet data to a JSON file or creates a new one."""
        try:
            if os.path.exists(filename):
                with open(filename, "r") as f:
                    existing_data = json.load(f)  # Load existing JSON array
            else:
                existing_data = []  # Empty list if no file

            existing_data.append(data)  # Append new data

            with open(filename, "w") as f:
                json.dump(existing_data, f, indent=4)

        except Exception as e:
            print(f"Error saving to JSON: {e}")
