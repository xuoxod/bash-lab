import logging
import re
from typing import Dict, Union

# Configure logging (adjust level and format as needed)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class PacketSanitizer:
    """
    Sanitizes network data while preserving the original for potential analysis.

    Attributes:
        data (Union[bytes, str]): The network data to be sanitized.
        sanitized_data (Union[bytes, str, None]): The sanitized network data.
        original_data (Union[bytes, str, None]): The original network data before sanitization.
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
    """

    def __init__(self):
        """Initializes the PacketSanitizer object."""
        self.logger = logging.getLogger(__name__)
        self.data = None
        self.sanitized_data = None
        self.original_data = None
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
            self.original_data = data
            if isinstance(data, str):
                self.sanitized_data = self._sanitize_string(data)
            elif isinstance(data, bytes):
                self.sanitized_data = self._sanitize_bytes(data)
            else:
                raise TypeError(
                    f"Unsupported data type: {type(data)}. Expected str or bytes."
                )
            return self.sanitized_data
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
        # Example: Replace IP addresses with '***.***.***.***'
        sanitized_data = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "***.***.***.***", data)
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
        # Example: Replace all occurrences of 'secret' with '*******'
        sanitized_data = data.replace(b"secret", b"*******")
        self.sanitization_map.update({data.decode(): sanitized_data.decode()})
        return sanitized_data

    def get_sanitization_map(self) -> Dict[str, str]:
        """
        Returns a dictionary mapping original data to sanitized data.

        Returns:
            Dict[str, str]: A dictionary where keys are original data segments and values are their sanitized counterparts.
        """
        return self.sanitization_map
