import unittest
from unittest.mock import patch
import socket
from network_modules.packetmaster import (
    _has_root_privileges,
    _get_mac_address,
    _send_custom_packet,
    scan_targets,
    _save_to_csv,  # Import the function you want to test
)


class TestPacketMaster(unittest.TestCase):
    # ... (other test methods)

    @patch("network_modules.packetmaster._send_custom_packet")
    def test_scan_targets_threading(self, mock_send_packet):
        """Test that scan_targets uses threading effectively."""
        mock_send_packet.return_value = ({}, "")  # Mock a successful response

        targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        scan_targets(targets, 80, "Test data", "tcp")

        # Check if _send_custom_packet was called for each target
        self.assertEqual(mock_send_packet.call_count, len(targets))

    @patch("network_modules.packetmaster.os.geteuid")
    def test_has_root_privileges(self, mock_geteuid):
        """Test _has_root_privileges function."""
        # Test case 1: User has root privileges
        mock_geteuid.return_value = 0
        self.assertTrue(_has_root_privileges())

        # Test case 2: User does not have root privileges
        mock_geteuid.return_value = 1000  # Example non-root UID
        self.assertFalse(_has_root_privileges())

    @patch("network_modules.packetmaster.csv.DictWriter")
    @patch("network_modules.packetmaster.open")
    def test_save_to_csv(self, mock_open, mock_csv_writer):
        """Test _save_to_csv function."""
        test_data = [
            {"Target": "192.168.1.1", "Port": 80, "Status": "Open"},
            {"Target": "192.168.1.2", "Port": 443, "Status": "Closed"},
        ]
        filename = "test_output.csv"

        _save_to_csv(test_data, filename)

        # Assertions
        mock_open.assert_called_once_with(filename, "w", newline="")
        mock_csv_writer.return_value.writeheader.assert_called_once()
        mock_csv_writer.return_value.writerows.assert_called_once_with(test_data)


if __name__ == "__main__":
    unittest.main()
