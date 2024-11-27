class NetworkSnifferError(Exception):
    """Base class for exceptions in the network sniffer module."""

    pass


class SocketCreationError(NetworkSnifferError):
    """Raised when there's an error creating the raw socket."""

    pass


class SocketBindingError(NetworkSnifferError):
    """Raised when there's an error binding the socket to the interface."""

    pass


class DefaultInterfaceNotFoundError(Exception):
    """Raised when the default network interface cannot be determined."""

    pass
