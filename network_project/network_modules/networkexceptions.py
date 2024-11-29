# networkexceptions.py


class NetworkError(Exception):  # A more general base class
    """Base class for exceptions related to network operations."""

    pass


class InterfaceError(NetworkError):  # Category for interface issues
    """Base class for exceptions related to network interfaces."""

    pass


class DefaultInterfaceNotFoundError(InterfaceError):  # More specific
    """Raised when the default network interface cannot be determined."""

    pass


class InterfaceConfigurationError(InterfaceError):
    """Raised when there's an issue with the network interface configuration."""


class AddressResolutionError(NetworkError):
    """Raised when MAC address resolution fails."""

    def __init__(self, ip_address, message=None):
        self.ip_address = ip_address
        self.message = message or f"Could not resolve MAC address for {ip_address}"
        super().__init__(self.message)


class PacketProcessingError(NetworkError):
    """Raised when there is an error processing a network packet."""


class PacketQueueFullError(NetworkError):
    """Raised when the packet queue is full."""

    pass


class ARPError(NetworkError):
    """Base class for exceptions related to ARP operations."""

    pass


class ARPRestorationError(ARPError):
    """Raised when there's an error restoring the ARP table."""

    pass


class PacketSendError(NetworkError):  # New exception class
    """Raised when there's an error sending a packet."""

    pass


class PacketReceiveError(NetworkError):  # New exception class
    """Raised when there's an error receiving a packet."""


class InvalidPacketFormatError(PacketProcessingError):  # New exception class
    """Raised when a packet has an invalid format."""

    pass


# (Existing Socket exceptions remain)
class SocketError(NetworkError):  # General Socket error (for consistency)
    """Base class for socket-related errors."""

    pass


class SocketCreationError(SocketError):
    """Raised when there's an error creating the raw socket."""

    pass


class SocketBindingError(SocketError):
    """Raised when there's an error binding the socket to the interface."""

    pass
