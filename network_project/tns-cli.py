#!/usr/bin/python3

import argparse
import sys
from network_modules.threadednmapscanner import ThreadedNmapScanner


def main():
    """Provides a command-line interface for the ThreadedNmapScanner."""

    parser = argparse.ArgumentParser(
        description="Perform network scans using multiple scan types and save results to a CSV file.",
        epilog="""
        Examples:
            # Scan 192.168.1.100 on ports 80 and 443 (no CSV output)
            python tns_cli.py -t 192.168.1.100 -p 80,443 

            # Scan 192.168.1.0/24 using default settings and save to default CSV
            python tns_cli.py -t 192.168.1.0/24 -s

            # Scan 192.168.1.1-192.168.1.10, save to custom CSV, and use UDP scan (type 3)
            python tns_cli.py -t 192.168.1.1-192.168.1.10 -o my_scan.csv -T 3
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required argument for target specification
    parser.add_argument(
        "-t",
        "--targets",
        required=True,
        help="Specify the target IP address(es) or hostname(s) to scan (e.g., 192.168.1.1, 192.168.1.0/24, google.com)",
    )

    # Optional arguments for ports, scan type, and CSV output
    parser.add_argument(
        "-p",
        "--ports",
        help="Specify custom ports to scan (e.g., 80,443,8080-8085). If not provided, the top 100 common ports will be used.",
    )
    parser.add_argument(
        "-T",
        "--scan-type",
        type=int,
        choices=range(1, len(ThreadedNmapScanner.SCAN_TYPES) + 1),
        help="Select a scan type from the list (enter the corresponding number):\n"
        + "\n".join(
            [f"{i}. {name}" for i, name in enumerate(ThreadedNmapScanner.SCAN_TYPES, 1)]
        ),
    )
    parser.add_argument(
        "-s",
        "--save",
        action="store_true",
        help="Save the scan results to the default CSV file (tns_scan_results.csv).",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILENAME",
        help="Save the scan results to a custom CSV file.",
    )

    args = parser.parse_args()

    # Create a ThreadedNmapScanner instance
    scanner = ThreadedNmapScanner(args.targets)

    # Handle port selection
    if args.ports:
        try:
            scanner.add_ports(args.ports)
        except ValueError as e:
            print(f"Error: Invalid port specification: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        scanner.add_common_ports()

    # Handle scan type selection
    if args.scan_type:
        selected_scan_type = list(ThreadedNmapScanner.SCAN_TYPES.keys())[
            args.scan_type - 1
        ]
        scanner.scan_type = selected_scan_type
    else:
        # Set default scan type (you can customize this)
        scanner.scan_type = "1"

    # Perform the scan
    scan_results = scanner.run_scan()

    # Print scan results to console
    for result in scan_results:
        print(result)

    # Save results to CSV if requested
    if args.save or args.output:
        filename = args.output if args.output else "tns_scan_results.csv"
        try:
            scanner.save_to_csv(filename)
            print(f"Scan results saved to {filename}")
        except Exception as e:
            print(f"Error saving results to CSV: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
