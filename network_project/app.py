#!/usr/bin/python3

from network_modules.nmap_port_scanner import CustomNmapScanner


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
        "Select common ports (enter numbers comma-separated, leave blank for none): "
    )

    custom_ports_input = input(
        "Enter custom ports (comma-separated or ranges, leave blank for none): "
    )

    # Combine common and custom ports
    if common_ports_input:
        selected_common_ports = [
            CustomNmapScanner.COMMON_PORTS[key]["ports"]
            for key in common_ports_input.split(",")
        ]
        ports = ",".join(selected_common_ports)
        if custom_ports_input:
            ports += f",{custom_ports_input}"
    else:
        ports = custom_ports_input  # Use custom ports or None

    scanner = CustomNmapScanner(targets, ports, scan_type)

    try:
        scanner.scan(targets)
    except KeyboardInterrupt:
        scanner.stop()


if __name__ == "__main__":
    main()
