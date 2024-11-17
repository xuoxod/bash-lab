import csv
import json
import hashlib  # For duplicate packet handling
import logging

# Configure logging (adjust level and format as needed)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class PacketSaver:
    # ... (your existing __init__ method)

    def save_packet_data(self, packet_data):
        """Saves packet data to both CSV and JSON files, avoiding duplicates."""
        packet_hash = hashlib.sha256(
            json.dumps(packet_data, sort_keys=True).encode()
        ).hexdigest()

        if packet_hash not in self.seen_packets:
            self.seen_packets.add(packet_hash)
            self._save_to_csv(packet_data, self.csv_filename)
            self._save_to_json(packet_data, self.json_filename)

    def save_packet_data(self, packet_data, filename):
        try:
            if filename.endswith(".csv"):
                with open(filename, "a", newline="", encoding="utf-8") as csvfile:
                    fieldnames = packet_data.keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    if csvfile.tell() == 0:  # write header only if file is empty
                        writer.writeheader()
                    writer.writerow(packet_data)
            elif filename.endswith(".json"):
                with open(filename, "a", encoding="utf-8") as jsonfile:
                    json.dump(packet_data, jsonfile, indent=4)
                    jsonfile.write(
                        "\n"
                    )  # Add a newline to separate json objects when appending
            else:
                print(f"Unsupported file type: {filename}")
        except Exception as e:
            print(f"Error saving packet data: {e}")

    def _save_to_csv(self, packet_data, filename):
        """Saves packet data to a CSV file."""
        try:
            with open(filename, "a", newline="") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=packet_data.keys())
                if csvfile.tell() == 0:  # Write header only if file is empty
                    writer.writeheader()
                writer.writerow(packet_data)
            logging.info(f"Packet data saved to CSV: {filename}")  # Log successful save
        except Exception as e:
            logging.error(f"Error saving to CSV: {e}")  # Log the error
            print(f"Error saving to CSV: {e}")  # Print the error to the console

    def _save_to_json(self, packet_data, filename):
        """Saves packet data to a JSON file."""
        try:
            with open(filename, "r+") as jsonfile:
                data = json.load(jsonfile)
                data.append(packet_data)
                jsonfile.seek(0)
                json.dump(data, jsonfile, indent=4)
            logging.info(
                f"Packet data saved to JSON: {filename}"
            )  # Log successful save
        except FileNotFoundError:
            with open(filename, "w") as jsonfile:
                json.dump([packet_data], jsonfile, indent=4)
            logging.info(
                f"Packet data saved to JSON: {filename}"
            )  # Log successful save
        except Exception as e:
            logging.error(f"Error saving to JSON: {e}")  # Log the error
            print(f"Error saving to JSON: {e}")  # Print the error to the console
