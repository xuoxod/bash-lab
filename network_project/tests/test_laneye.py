import unittest
import scapy.all as scapy
from unittest.mock import patch
from network_modules.laneye import NetworkScanner


class TestLaneyeScan(unittest.TestCase):

    @patch("scapy.all.srp")  # Mock scapy.srp
    def test_valid_target(self, mock_srp):
        # Set up mock data for scapy.srp to return
        mock_srp.return_value = (
            [
                (None, scapy.ARP(psrc="192.168.1.1", hwsrc="AA:BB:CC:DD:EE:FF")),
                (None, scapy.ARP(psrc="192.168.1.2", hwsrc="00:11:22:33:44:55")),
            ],
            [],  # Empty list for unanswered packets
        )

        scanner = NetworkScanner()
        results = scanner.scan_network("192.168.1.0/24")

        # Assertions
        self.assertEqual(results["192.168.1.1"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(results["192.168.1.2"], "00:11:22:33:44:55")

    # Add more test cases for invalid targets, output formats, etc.
    @patch("scapy.all.srp")
    def test_invalid_targets(self, mock_srp):
        # Test with incorrect IP addresses
        with self.assertRaises(ValueError) as context:
            scanner = NetworkScanner()
            scanner.scan_network("192.168.1")
        self.assertIn(
            "'192.168.1' does not appear to be an IPv4 or IPv6 network",  # Actual error message
            str(context.exception),
        )

        # Test with invalid CIDR ranges
        with self.assertRaises(ValueError) as context:
            scanner = NetworkScanner()
            scanner.scan_network("192.168.1.0/33")  # Invalid CIDR range
        self.assertIn(
            "'192.168.1.0/33' does not appear to be an IPv4 or IPv6 network",  # Actual error message
            str(context.exception),
        )

        # Test with other invalid input
        with self.assertRaises(ValueError) as context:
            scanner = NetworkScanner()
            scanner.scan_network("invalid-input")
        self.assertIn(
            "'invalid-input' does not appear to be an IPv4 or IPv6 network",
            str(context.exception),
        )
