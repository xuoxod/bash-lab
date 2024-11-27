#!/usr/bin/python3


import scapy.all as scapy
import netifaces
import argparse
import subprocess
import threading
import time


class Rerouter:

    def __init__(self, target_ip, interface=None, gateway_ip=None, verbose=True):
        self.target_ip = target_ip
        self.verbose = verbose
        self.bridge_name = "br0"
        self.stop_event = threading.Event()

        # Interface handling
        if interface:  # An interface was provided
            self.interface_name = interface
            try:
                self.interface = scapy.get_if_list()[
                    scapy.get_if_list().index(self.interface_name)
                ]
            except ValueError as e:
                self._print(
                    f"The supplied interface {interface} was not found: {str(e)}",
                    color="red",
                )
                raise

        else:  # No interface supplied
            try:
                default_gw = netifaces.gateways()[
                    "default"
                ]  # Get default gateway data from OS.
                self.interface_name = default_gw[netifaces.AF_INET][
                    1
                ]  # Interface name is in the gateway data
                self.interface = scapy.get_if_list()[
                    scapy.get_if_list().index(self.interface_name)
                ]
                self._print(
                    f"Using default interface: {self.interface_name}", color="green"
                )  # Notify using default interface.
            except (KeyError, IndexError, ValueError) as e:
                self._print(
                    f"Could not determine default interface: {str(e)}", color="red"
                )
                raise ValueError("No valid network interface found.")

        # Gateway IP resolution
        if gateway_ip:  # Use provided gateway if given
            self.gateway_ip = gateway_ip
        else:  # Resolve gateway IP if none provided.
            try:
                self.gateway_ip = netifaces.gateways()["default"][netifaces.AF_INET][0]
                self._print(f"Using gateway IP: {self.gateway_ip}", color="green")
            except (KeyError, IndexError) as e:
                self._print(f"Could not get gateway IP: {str(e)}", color="red")
                raise ValueError("Failed to determine default gateway")

        # Get Interface IP and MAC
        try:
            self.interface_ip = netifaces.ifaddresses(self.interface_name)[
                netifaces.AF_INET
            ][0]["addr"]
            self.interface_mac = netifaces.ifaddresses(self.interface_name)[
                netifaces.AF_LINK
            ][0]["addr"]

            self._print(f"Interface IP: {self.interface_ip}", color="green")
            self._print(f"Interface MAC: {self.interface_mac}", color="green")

        except (KeyError, IndexError, ValueError) as e:
            self._print(f"Could not get Interface IP or MAC: {str(e)}", color="red")
            raise ValueError("Failed to determine default Interface IP or MAC")

        # Get MAC addresses. (moved here, after interface and gateway resolution).
        self.target_mac = self._get_mac(self.target_ip)
        self.gateway_mac = self._get_mac(self.gateway_ip)

        if not self.target_mac:
            self._print(
                f"Could not resolve target MAC for {self.target_ip}.", color="red"
            )
        if not self.gateway_mac:
            self._print(
                f"Could not resolve gateway MAC for {self.gateway_ip}.", color="red"
            )

    # Add a _get_mac method.
    def _get_mac(self, ip):
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=2,
                verbose=0,
                iface=self.interface_name,
            )
            if ans:
                return ans[0][1].hwsrc
            return None
        except Exception as e:
            self._print(f"Error getting MAC: {e}", color="red")
            return None

    def _print(self, msg, color="green"):
        if self.verbose:
            print(f"[{color}]{msg}[/]")

    def _setup_bridge(self):
        """Creates and configures the bridge interface."""
        try:
            # Check if bridge already exists
            subprocess.run(
                ["ip", "link", "show", self.bridge_name],
                capture_output=True,
                check=False,
            )
        except subprocess.CalledProcessError as e:
            if e.returncode == 1:  # Bridge doesn't exist, create it.
                try:
                    subprocess.run(
                        ["ip", "link", "add", self.bridge_name, "type", "bridge"],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    self._print(f"Bridge interface {self.bridge_name} created.")

                except subprocess.CalledProcessError as e:
                    self._print(f"Error creating bridge: {e.stderr}", color="red")
                    raise  # Re-raise
            else:  # Some other error creating the bridge
                raise  # Re-raise the original exception

        try:
            # Bring physical interface down
            subprocess.run(
                ["ip", "link", "set", self.interface_name, "down"],
                check=True,
                capture_output=True,
                text=True,
            )
            self._print(f"Interface {self.interface_name} is down.")

            # Add physical interface to bridge
            subprocess.run(
                ["ip", "link", "set", self.interface_name, "master", self.bridge_name],
                check=True,
                capture_output=True,
                text=True,
            )
            self._print(
                f"Interface {self.interface_name} added to bridge {self.bridge_name}."
            )

            # Bring the bridge up
            subprocess.run(
                ["ip", "link", "set", self.bridge_name, "up"],
                check=True,
                capture_output=True,
                text=True,
            )
            self._print(f"Bridge interface {self.bridge_name} is up.")

        except subprocess.CalledProcessError as e:
            self._print(f"Error setting up bridge: {e.stderr}", color="red")
            raise  # Re-raise

    def _remove_bridge(self):
        try:
            # Attempt to detach the interface, but don't stop if it fails
            try:
                subprocess.run(
                    ["ip", "link", "set", self.interface_name, "master", "none"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self._print(
                    f"Interface {self.interface_name} detached from bridge.",
                    color="green",
                )  # Indicate success
            except subprocess.CalledProcessError as detach_error:
                self._print(
                    f"Error detaching interface: {detach_error.stderr}", color="yellow"
                )  # Report, but continue

            # Always try to delete the bridge, even if detach failed.
            subprocess.run(
                ["ip", "link", "delete", self.bridge_name],
                check=True,
                capture_output=True,
                text=True,
            )
            self._print(f"Bridge interface {self.bridge_name} removed.", color="green")

        except subprocess.CalledProcessError as remove_error:
            self._print(
                f"Error removing bridge: {remove_error.stderr}", color="red"
            )  # Report removal errors.

    def _forward_traffic(self):
        try:

            def _should_stop(packet):  # Custom stop filter function
                return self.stop_event.is_set()

            sniffer = scapy.AsyncSniffer(
                filter=f"host {self.target_ip} and not (ether dst {scapy.get_if_hwaddr(self.interface_name)})",
                prn=lambda x: scapy.send(x, iface=self.bridge_name),  # Forward packets
                store=False,
                iface=self.interface_name,  # Use interface name directly
                stop_filter=_should_stop,  # Use the custom stop function
            )
            sniffer.start()  # Start sniffing asynchronously

            while not self.stop_event.is_set():  # Check the stop event periodically
                time.sleep(0.1)  # Small delay to avoid busy-waiting.

            sniffer.stop()  # Stop sniffing gracefully

        except Exception as e:
            self._print(f"Error forwarding traffic: {e}", color="red")

    def start(self):
        try:
            self._setup_bridge()

            # Explicitly check if forwarding_thread was created before proceeding.
            try:
                self.forwarding_thread = threading.Thread(
                    target=self._forward_traffic, daemon=True
                )
                self.forwarding_thread.start()
                self._print("Forwarding thread started.", color="green")
            except Exception as thread_error:
                self._print(
                    f"Error starting forwarding thread: {thread_error}", color="red"
                )
                raise  # Re-raise to trigger the outer except block and attempt cleanup

            self._print("Rerouting started.")

            while True:
                if self.stop_event.is_set():
                    self.stop()
                    return  # Exit after calling stop()

                time.sleep(1)

        except (
            Exception
        ) as e:  # Handle any errors during startup, including forwarding thread issues.
            self._print(f"Error starting rerouting: {str(e)}", color="red")
            self.stop()  # Attempt cleanup even if starting failed.

    def stop(self):
        self._print("Stopping rerouting...")
        self.stop_event.set()

        if hasattr(
            self, "forwarding_thread"
        ):  # Only try to join if forwarding thread has been started
            try:
                self.forwarding_thread.join(timeout=2.0)
                if self.forwarding_thread.is_alive():
                    self._print(
                        "Forwarding thread did not exit within timeout.", color="yellow"
                    )
                else:
                    self._print(
                        f"Forwarding thread exited normally: {self.forwarding_thread.name}",
                        color="green",
                    )  # Show thread name

            except Exception as removal_error:
                self._print(
                    f"Error joining forwarding thread: {str(removal_error)}",
                    color="red",
                )  # Print specific exception

        try:
            self._remove_bridge()
        except Exception as removal_error:
            self._print(
                f"Encountered an issue removing the bridge: {str(removal_error)}\n",
                color="red",
            )

        # After attempting bridge removal try and bring the interface back up.
        try:
            subprocess.run(
                ["ip", "link", "set", self.interface_name, "up"],
                check=True,
                capture_output=True,
                text=True,
            )  # Bring interface back up
            self._print(f"Interface {self.interface_name} set to up.", color="green")
        except subprocess.SubprocessError as iface_error:
            self._print(
                f"Error setting up interface {self.interface_name} during stop(): {str(iface_error)}",
                color="red",
            )
            if self.verbose:
                self.console.print_exception()  # Print exception if verbose is enabled.

        self._print("Rerouting stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Reroutes network traffic for a target IP."
    )
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("-i", "--interface", help="Network interface (optional)")
    parser.add_argument(
        "-g",
        "--gateway",
        dest="gateway_ip",
        help="Gateway IP address (optional)",  # Correctly get gateway IP
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    try:
        rerouter = Rerouter(
            args.target_ip, args.interface, args.gateway_ip, args.verbose
        )  # Pass gateway_ip correctly
        rerouter.start()
        while True:
            time.sleep(1)

    except ValueError as ve:  # More specific error catching:
        print(f"[bold red]{ve}[/]")  # Print the ValueError message
        parser.print_help()  # Show help
        exit(1)  # Indicate error
    except KeyboardInterrupt:
        print("Stopping...")
        if (
            "rerouter" in locals()
        ):  # Check if rerouter instance was created successfully
            rerouter.stop()  # If so call .stop() method
    except Exception as e:  # Catch-all for any other exceptions:
        print(f"An unexpected error occurred: {str(e)}")  # Show error
        if "rerouter" in locals():  # Check if we can call stop
            rerouter.stop()  # Attempt to clean up
