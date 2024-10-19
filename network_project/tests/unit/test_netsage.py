# test_netsage.py
import unittest
import io
import sys
from netsage import main  # Import your main function
from network_modules.helpers.colors import TextColors


class TestNetSage(unittest.TestCase):
    def test_scan_valid_ip(self):
        """Test scanning a valid IP address."""
        sys.argv = [
            "netsage.py",
            "scan",
            "127.0.0.1",  # Use localhost for a reliable test
            "-p",
            "80,443",
        ]
        captured_output = io.StringIO()
        sys.stdout = captured_output
        main()
        sys.stdout = sys.__stdout__

        output = captured_output.getvalue()
        self.assertIn(f"{TextColors.OKGREEN}[+] 127.0.0.1:{TextColors.ENDC}", output)

        # Adjust these port checks based on your system
        # self.assertIn("Port 80: Open", output)
        # self.assertIn("Port 443: Open", output)

    def test_scan_invalid_ip(self):
        """Test handling of an invalid IP address."""
        sys.argv = ["netsage.py", "scan", "this.is.not.an.ip"]
        captured_output = io.StringIO()
        sys.stdout = captured_output

        with self.assertRaises(SystemExit) as cm:
            main()

        sys.stdout = sys.__stdout__
        self.assertEqual(cm.exception.code, 1)  # Expect exit code 1 for error

        output = captured_output.getvalue()
        self.assertIn("Invalid IP address", output)  # Check for error message

    # Add more test cases for different scenarios (CIDR ranges,
    # invalid ports, port ranges, etc.)


if __name__ == "__main__":
    unittest.main()
