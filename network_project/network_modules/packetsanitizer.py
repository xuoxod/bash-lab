import logging
import re
import sys
import argparse
from typing import Dict, Union

# Configure logging (adjust level and format as needed)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class PacketSanitizer:
    """
    Sanitizes network data while preserving the original for potential analysis.

    This class can be used either programmatically or from the command line.

    Attributes:
        sanitization_map (Dict[str, str]): A dictionary mapping original data to sanitized data.

    Methods:
        sanitize(self, data: Union[bytes, str]) -> Union[bytes, str, None]:
            Sanitizes the provided network data.
        _sanitize_string(self, data: str) -> str:
            Sanitizes string data.
        _sanitize_bytes(self, data: bytes) -> bytes:
            Sanitizes bytes data.
        get_sanitization_map(self) -> Dict[str, str]:
            Returns a dictionary mapping original data to sanitized data.
        main():
            Provides a command-line interface for the sanitizer.
    """

    def __init__(self):
        """Initializes the PacketSanitizer object."""
        self.logger = logging.getLogger(__name__)
        self.sanitization_map = {}

    def sanitize(self, data: Union[bytes, str]) -> Union[bytes, str, None]:
        """
        Sanitizes the provided network data.

        Args:
            data (Union[bytes, str]): The network data to be sanitized.

        Returns:
            Union[bytes, str, None]: The sanitized network data, or None if an error occurred.
        """
        try:
            if isinstance(data, str):
                return self._sanitize_string(data)
            elif isinstance(data, bytes):
                return self._sanitize_bytes(data)
            else:
                raise TypeError(
                    f"Unsupported data type: {type(data)}. Expected str or bytes."
                )
        except Exception as e:
            self.logger.error(f"Error sanitizing data: {e}")
            return None

    def _sanitize_string(self, data: str) -> str:
        """
        Sanitizes string data.

        Args:
            data (str): The string data to be sanitized.

        Returns:
            str: The sanitized string data.
        """
        # Example: Replace IP addresses and email addresses
        sanitized_data = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "***.***.***.***", data)
        sanitized_data = re.sub(r"[\w.-]+@[\w.-]+", "****@****.***", sanitized_data)
        self.sanitization_map.update({data: sanitized_data})
        return sanitized_data

    def _sanitize_bytes(self, data: bytes) -> bytes:
        """
        Sanitizes bytes data.

        Args:
            data (bytes): The bytes data to be sanitized.

        Returns:
            bytes: The sanitized bytes data.
        """
        # Example: Replace all occurrences of 'secret' and 'password'
        sanitized_data = data.replace(b"secret", b"*******")
        sanitized_data = sanitized_data.replace(b"password", b"********")
        self.sanitization_map.update(
            {data.decode(): sanitized_data.decode()}
        )  # Update map with decoded values
        return sanitized_data

    def get_sanitization_map(self) -> Dict[str, str]:
        """
        Returns a dictionary mapping original data to sanitized data.

        Returns:
            Dict[str, str]: A dictionary where keys are original data segments and
            values are their sanitized counterparts.
        """
        return self.sanitization_map

    def main(self):
        """Provides a command-line interface for the sanitizer."""
        parser = argparse.ArgumentParser(
            description="Sanitize network data.",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument(
            "data",
            nargs="?",  # Make the 'data' argument optional
            help="The network data to sanitize. If not provided, data will be read from standard input.",
        )
        args = parser.parse_args()

        if args.data:
            data = args.data
        else:
            print(
                "Enter the network data you want to sanitize (press Ctrl+D to finish input):"
            )
            data = sys.stdin.read()

        sanitized_data = self.sanitize(data)
        if sanitized_data is not None:
            print("Sanitized Data:")
            print(sanitized_data)
        else:
            print("An error occurred during sanitization.")


if __name__ == "__main__":
    sanitizer = PacketSanitizer()
    sanitizer.main()
