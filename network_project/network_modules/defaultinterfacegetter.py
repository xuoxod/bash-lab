import netifaces
from networkexceptions import DefaultInterfaceNotFoundError


class DefaultInterfaceGetter:
    @staticmethod
    def get_default_interface():
        """Determines the default network interface."""
        try:
            gws = netifaces.gateways()
            default_gateway = gws["default"][netifaces.AF_INET]
            return default_gateway[1]  # Interface name
        except KeyError as exc:
            raise DefaultInterfaceNotFoundError(
                "No default gateway found. Are you connected to a network?"
            ) from exc
