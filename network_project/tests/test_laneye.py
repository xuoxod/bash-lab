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
