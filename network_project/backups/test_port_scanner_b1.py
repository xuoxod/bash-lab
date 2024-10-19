# /home/rick/private/projects/desktop/bash/scratch/network_project/tests/unit/test_port_scanner.py
import unittest
from network_modules.port_scanner import PortScanner  # Update the import path


class TestPortScanner(unittest.TestCase):
    def setUp(self):
        """Setup method to create a PortScanner instance for testing."""
        self.scanner = PortScanner()

    def test_scan_port_open(self):
        """Test with a known open port (e.g., 80 on a web server)."""
        self.assertTrue(self.scanner.scan_port("google.com", 80))

    def test_scan_port_closed(self):
        """Test with a likely closed port."""
        self.assertFalse(self.scanner.scan_port("google.com", 55555))

    # Add more tests for port_scanner.py here, for example:
    def test_scan_network_with_valid_ip(self):
        """Test scanning a single valid IP address."""
        results = self.scanner.scan_network("127.0.0.1", [22, 80, 443])
        self.assertIn("127.0.0.1", results)
        # Add assertions based on your system's open ports

    def test_scan_network_with_cidr_range(self):
        """Test scanning a CIDR range (adjust range if needed)."""
        results = self.scanner.scan_network("192.168.1.0/24", [80, 443])
        # Adjust assertions based on your network configuration
        self.assertGreater(len(results), 0)  # Expect at least one result

    def test_scan_network_with_invalid_input(self):
        """Test handling of invalid input to scan_network."""
        with self.assertRaises(ValueError):
            self.scanner.scan_network("invalid-ip", [80])


if __name__ == "__main__":
    unittest.main()
