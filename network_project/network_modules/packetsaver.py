import csv
import json
import hashlib  # For duplicate packet handling


class PacketSaver:
    def __init__(
        self, csv_filename="packet_data.csv", json_filename="packet_data.json"
    ):
        self.csv_filename = csv_filename
        self.json_filename = json_filename
        self.seen_packets = set()  # To store hashes of seen packets

    def save_packet_data(self, packet_data):
        """Saves packet data to both CSV and JSON files, avoiding duplicates."""
        packet_hash = hashlib.sha256(
            json.dumps(packet_data, sort_keys=True).encode()
        ).hexdigest()

        if packet_hash not in self.seen_packets:
            self.seen_packets.add(packet_hash)
            self._save_to_csv(packet_data, self.csv_filename)
            self._save_to_json(packet_data, self.json_filename)

    def _save_to_csv(self, packet_data, filename):
        """Saves packet data to a CSV file."""
        try:
            with open(filename, "a", newline="") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=packet_data.keys())
                if csvfile.tell() == 0:  # Write header only if file is empty
                    writer.writeheader()
                writer.writerow(packet_data)
        except Exception as e:
            print(f"Error saving to CSV: {e}")

    def _save_to_json(self, packet_data, filename):
        """Saves packet data to a JSON file."""
        try:
            with open(filename, "r+") as jsonfile:
                data = json.load(jsonfile)
                data.append(packet_data)
                jsonfile.seek(0)
                json.dump(data, jsonfile, indent=4)
        except FileNotFoundError:
            with open(filename, "w") as jsonfile:
                json.dump([packet_data], jsonfile, indent=4)
        except Exception as e:
            print(f"Error saving to JSON: {e}")
