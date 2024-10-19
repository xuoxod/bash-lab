from network_modules.helpers.colors import TextColors


def parse_ports(port_args):
    """Parses and validates port arguments.

    Args:
        port_args: A list of port arguments (strings or integers).

    Returns:
        A list of valid port numbers (integers), or an empty list if no valid ports are found.
    """
    ports_to_scan = []
    for port_arg in port_args:
        if isinstance(port_arg, str):
            for port in port_arg.split(","):
                try:
                    port = int(port)
                    if not (1 <= port <= 65535):
                        print(
                            f"{TextColors.WARNING}Invalid port number: {port}{TextColors.ENDC}"
                        )
                    else:
                        ports_to_scan.append(port)
                except ValueError:
                    print(
                        f"{TextColors.WARNING}Invalid port format: {port}{TextColors.ENDC}"
                    )
        elif isinstance(port_arg, int):
            if not (1 <= port_arg <= 65535):
                print(
                    f"{TextColors.WARNING}Invalid port number: {port_arg}{TextColors.ENDC}"
                )
            else:
                ports_to_scan.append(port_arg)
        else:
            print(
                f"{TextColors.WARNING}Invalid port format: {port_arg}{TextColors.ENDC}"
            )
    return ports_to_scan
