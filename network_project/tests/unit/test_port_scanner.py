# test_port_scanner.py
import unittest
import io
import sys

from network_modules.port_scanner import PortScanner, _validate_target


class TestPortScanner(unittest.TestCase):
    def setUp(self):
        """Setup method to create a PortScanner instance for testing."""
        self.scanner = PortScanner(timeout=0.5, max_threads=10)  # Adjust as needed

    def test_scan_port_directly(self):
        scanner = PortScanner(timeout=0.1)  # Very short timeout
        result = scanner.scan_port("google.com", 80)  # Known open port
        self.assertTrue(result)  # Should be True if the port is open

    def test_scan_port_open(self):
        """Test with a known open port (e.g., 80 on a web server)."""
        self.assertTrue(self.scanner.scan_port("google.com", 80))

    def test_scan_port_closed(self):
        """Test with a likely closed port."""
        self.assertFalse(self.scanner.scan_port("google.com", 55555))

    def test_scan_network_with_valid_ip(self):
        """Test scanning a single valid IP address."""
        results = self.scanner.scan_network("127.0.0.1", [22, 80, 443])
        self.assertIn("127.0.0.1", results)
        # Add assertions based on your system's open ports

    def test_scan_network_with_cidr_range(self):
        """Test scanning a CIDR range (adjust range if needed)."""
        scanner = PortScanner(timeout=0.5, max_threads=10)
        results = scanner.scan_network("127.0.0.1/32", [80, 443])  # Scan localhost only
        # Adjust assertions based on your network configuration
        self.assertGreater(len(results), 0)  # Expect at least one result

    def test_scan_network_with_invalid_input(self):
        """Test handling of invalid input to scan_network."""
        with self.assertRaises(ValueError):
            self.scanner.scan_network("invalid-ip", [80])

    def test_validate_target_valid_ip(self):
        """Test validation of a valid IP address."""
        self.assertIsNone(_validate_target("192.168.1.1"))

    def test_validate_target_valid_cidr(self):
        """Test validation of a valid CIDR range."""
        self.assertIsNone(_validate_target("192.168.1.0/24"))

    def test_validate_target_invalid_ip(self):
        """Test validation of an invalid IP address."""
        with self.assertRaises(ValueError):
            _validate_target("invalid-ip")

    def test_validate_target_invalid_cidr(self):
        """Test validation of an invalid CIDR range."""
        with self.assertRaises(ValueError):
            _validate_target("192.168.1.1/33")  # Invalid CIDR

        def test_print_results_with_open_ports(self):
            """Test printing results when ports are open."""
            results = {"127.0.0.1": [80, 443]}
            captured_output = io.StringIO()
            sys.stdout = captured_output
            self.scanner.raw_print_results(results)
            sys.stdout = sys.__stdout__
            output = captured_output.getvalue()
            self.assertIn("[+] 127.0.0.1:", output)
            self.assertIn("\tPort 80: Open", output)
            self.assertIn("\tPort 443: Open", output)

        def test_print_results_with_no_open_ports(self):
            """Test printing results when no ports are open."""
            results = {"127.0.0.1": []}
            captured_output = io.StringIO()
            sys.stdout = captured_output
            self.scanner.print_results(results)
            sys.stdout = sys.__stdout__
            output = captured_output.getvalue()
            self.assertIn("[+] 127.0.0.1:", output)
            self.assertIn("\tNo open ports found", output)


if __name__ == "__main__":
    unittest.main()
