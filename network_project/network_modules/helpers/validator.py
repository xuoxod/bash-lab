class ValidateIP(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        try:
            ipaddress.ip_address(values)  # Validate IP
            setattr(namespace, self.dest, values)
        except ValueError:
            raise argparse.ArgumentTypeError("Invalid IP address.")


parser.add_argument("--ip", action=ValidateIP)
