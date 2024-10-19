# tests/unit/test_scapy_port_scanner.py

import unittest
from unittest.mock import patch, MagicMock
from scapy.all import IP, TCP, ICMP
from network_modules.scapy_port_scanner import ScapyPortScanner


class TestScapyPortScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = ScapyPortScanner(timeout=0.1)

    @patch("network_modules.scapy_port_scanner.sr1")
    def test_scan_port_open(self, mock_sr1):
        """Test scanning an open port."""
        mock_response = IP(dst="127.0.0.1") / TCP(
            sport=80, dport=8080, flags="SA"
        )  # SYN-ACK
        mock_sr1.return_value = mock_response
        self.assertTrue(self.scanner.scan_port("127.0.0.1", 8080))

    @patch("network_modules.scapy_port_scanner.sr1")
    def test_scan_port_closed(self, mock_sr1):
        """Test scanning a closed port."""
        mock_response = IP(dst="127.0.0.1") / TCP(
            sport=80, dport=8081, flags="R"
        )  # RST
        mock_sr1.return_value = mock_response
        self.assertFalse(self.scanner.scan_port("127.0.0.1", 8081))

    @patch("network_modules.scapy_port_scanner.sr1")
    def test_scan_port_filtered(self, mock_sr1):
        """Test scanning a filtered port."""
        mock_response = IP(dst="127.0.0.1") / ICMP()  # ICMP response
        mock_sr1.return_value = mock_response
        self.assertFalse(self.scanner.scan_port("127.0.0.1", 8082))

    @patch("network_modules.scapy_port_scanner.sr1")
    def test_scan_port_timeout(self, mock_sr1):
        """Test scanning a port that times out."""
        mock_sr1.return_value = None  # Timeout
        self.assertFalse(self.scanner.scan_port("127.0.0.1", 8083))

    def test_scan_network(self):
        """Test scanning a network (mocking individual port scans)."""
        self.scanner.scan_port = MagicMock(side_effect=[True, False, True])
        results = self.scanner.scan_network(target=["192.168.1.1"], ports=[22, 80, 443])
        self.assertEqual(results["192.168.1.1"], [22, 443])

    # Add more test cases as needed, covering different scenarios and edge cases.
