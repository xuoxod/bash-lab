import unittest
import subprocess


class TestNetSageIntegration(unittest.TestCase):

    def test_scan_single_ip(self):
        # Use subprocess to run your script
        result = subprocess.run(
            ["python3", "netsage.py", "scan", "127.0.0.1", "-p", "80"],
            capture_output=True,
            text=True,
        )
        # Check for expected output in stdout
        # self.assertIn("Open port found", result.stdout)
        # print(f"Result: {result.stdout}")
        self.assertIn("No open ports found", result.stdout)

    # ... more tests for different command-line combinations
