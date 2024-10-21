#!/usr/bin/python3

from network_modules.nmportscan import CustomNmapScanner  # Corrected import path


def main():
    """Provides a console interface for running the nmap scanner."""

    targets = input(
        "Enter target IP address(es) or network range(s) (comma-separated): "
    )

    print("\nAvailable Scan Types:")
    for key, value in CustomNmapScanner.SCAN_TYPES.items():
        print(f"{key}: {value['name']}")
    scan_type = input("Select a scan type (enter number, leave blank for default): ")

    print("\nCommon Ports:")
    for key, value in CustomNmapScanner.COMMON_PORTS.items():
        print(f"{key}: {value['name']} ({value['ports']})")
    common_ports_input = input(
        "Select common ports (enter numbers comma-separated, leave blank for custom ports): "
    )
    if common_ports_input:
        selected_common_ports = [
            CustomNmapScanner.COMMON_PORTS[key]["ports"]
            for key in common_ports_input.split(",")
        ]
        ports = ",".join(selected_common_ports)
    else:
        ports = input(
            "Enter ports to scan (comma-separated or ranges, leave blank for default): "
        )

    scanner = CustomNmapScanner(targets, ports, scan_type)

    try:
        scanner.scan()
    except KeyboardInterrupt:
        scanner.stop()


if __name__ == "__main__":
    main()
