#!/usr/bin/python3

import argparse
import scapy.all as scapy
from netmapper import NetMapper


def main():
    parser = argparse.ArgumentParser(
        # ... (very detailed description and epilog as requested, with subcommands)
    )

    subparsers = parser.add_subparsers(
        dest="command", help="Available commands", required=True
    )

    # ... (Add subparsers for other commands/modules and their arguments)

    # Example for 'map' subcommand (using NetMapper)
    map_parser = subparsers.add_parser("map", help="Map network devices")
    map_parser.add_argument("targets", nargs="*", help="Target IP or network")
    map_parser.add_argument(
        "-o", "--output", choices=["json", "csv", "html"], help="Output format"
    )
    map_parser.add_argument("--filename", help="Output filename")  # filename option

    args = parser.parse_args()  # Parse the arguments

    if args.command == "map":  # Handle the "map" subcommand
        mapper = NetMapper()
        if not args.targets:  # If no targets are provided then scan default network
            target_network = (
                scapy.get_if_addr(scapy.conf.iface) + "/24"
            )  # Default network
            mapper.scan_network(target_network)

        else:  # If the targets argument is not empty
            for target in args.targets:  # Iterate thru the list of targets
                mapper.scan_network(target)

        mapper.print_results()  # Print results to the console
        if args.output:  # Handle --output (save to file)
            filename = (
                args.filename or "network_scan"
            )  # Use specified filename or default name
            mapper.save_results(format=args.output, filename=filename)
            print(f"Results saved to {filename}.{args.output}")

    # ... (Handle other commands/subparsers in a similar way)


if __name__ == "__main__":
    main()
