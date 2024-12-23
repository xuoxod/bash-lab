#!/usr/bin/python3


from typing import Text
import scapy.all as scapy
import netifaces
import argparse
import subprocess
import threading
import time

from prettyprint import PrettyPrint  # Import PrettyPrint
from queue import Queue, Empty  # For thread-safe communication
from rich.console import Console


class Rerouter:

    def __init__(self, target_ip, interface=None, gateway_ip=None, verbose=True):
        self.printer = PrettyPrint(title="Rerouter Status")  # Initialize PrettyPrint
        self.update_queue = Queue()  # Create update queue
        self.console = Console()  # Initialize Rich console
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

    def _print(self, message, color="green"):  # Corrected and more robust _print()
        if self.verbose:
            try:
                if isinstance(message, str):  # Check message type
                    text = Text(message)  # Create Text object from string

                    if color:  # Only apply style if a color string is supplied
                        text.stylize(color)  # Apply style. Now safe.

                    self.console.print(text)

                elif isinstance(message, Text):  # If it's already a Text object
                    if color:  # If a color is provided
                        message.stylize(
                            color
                        )  # Directly apply style to the Text object

                    self.console.print(message)

                else:  # If message is not string or Text
                    self.console.print(message)  # Let Rich handle non-string types.

            except Exception as e:  # Handle unexpected errors in printing.
                self.console.print(
                    f"[bold red]Error in _print(): {e}[/]"
                )  # Report error
                if self.verbose:
                    self.console.print_exception()  # Show full exception for debugging

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

            table_setup_complete = threading.Condition()  # For thread signaling

            self.pretty_print_thread = threading.Thread(
                target=self._pretty_print_loop, daemon=True
            )
            self.pretty_print_thread.start()

            self.forwarding_thread = threading.Thread(
                target=self._forward_traffic, daemon=True
            )
            self.forwarding_thread.start()

            self.printer.add_column(
                "Field", style="cyan", no_wrap=True
            )  # Ensure no_wrap is True for correct formatting
            self.printer.add_column(
                "Value", style="magenta", no_wrap=True
            )  # Ensure no_wrap is True for correct formatting

            self._add_table_row("Target IP", self.target_ip)
            self._add_table_row("Target MAC", self.target_mac)
            self._add_table_row("Gateway IP", self.gateway_ip)
            self._add_table_row("Gateway MAC", self.gateway_mac)
            self._add_table_row("Interface", self.interface_name)
            self._add_table_row("Interface IP", self.interface_ip)
            self._add_table_row("Interface MAC", self.interface_mac)
            self._add_table_row("Bridge", self.bridge_name)
            self._add_table_row("Status", "")  # Add "Status" row *before* updating it

            with table_setup_complete:  # Signal initial table is setup
                table_setup_complete.notify()  # Signal pretty print thread

            self.update_queue.put(
                ("update_cell", 8, 1, "[bold green]Rerouting...[/]")
            )  # Update status *after* adding all rows

            self._print("Rerouting started.")

            while True:
                if self.stop_event.is_set():
                    self.stop()
                    break  # Exit loop after calling stop()
                time.sleep(1)

        except Exception as e:
            # existing error handling, including calling self.stop() for cleanup
            self._print(
                f"Error starting rerouting: {str(e)}", color="red"
            )  # Provide information about error
            self.stop()  # Ensure cleanup even if starting failed

    def _add_table_row(self, field, value):  # Helper to add rows from start().
        self.update_queue.put(("add_row", field, value))

    def _pretty_print_loop(self, setup_complete):
        with setup_complete:
            setup_complete.wait()  # Wait for table setup to complete in the main thread

        while True:  # Continue until sentinel value is encountered.
            try:
                item = self.update_queue.get(timeout=1)  # Timeout for responsiveness
                if item is None:  # Check for sentinel value before unpacking.
                    self._print(
                        "Pretty print thread stopping...", color="yellow"
                    )  # Informative output
                    break  # Break the loop only on sentinel value

                action, *args = item

                # Same actions as before
                if action == "add_row":
                    self.printer.add_row(*args)  # Correct placement for add_row
                elif action == "update_cell":
                    self.printer.update_cell(*args)  # Thread-safe update

                self.printer.print_page()  # Refresh output

                pass  # Do not stop thread, continue looping until sentinel value is received or another error occurs

            except Exception as print_error:  # Handle unexpected printing errors.
                self._print(
                    f"[bold red]Error in pretty print loop: {print_error}[/]"
                )  # Report error
                if self.verbose:
                    self.console.print_exception()

    def stop(self):
        self._print("Stopping rerouting...", color="yellow")  # Console message.
        self._update_status("[bold yellow]Stopping...[/]")  # PrettyPrint update.
        self.stop_event.set()  # Signal other threads to stop.

        threads_to_join = []
        if hasattr(self, "forwarding_thread") and self.forwarding_thread.is_alive():
            threads_to_join.append(self.forwarding_thread)

        if (
            hasattr(self, "pretty_print_thread") and self.pretty_print_thread.is_alive()
        ):  # Join the pretty print thread first
            threads_to_join.append(self.pretty_print_thread)

        for thread in threads_to_join:
            thread_name = thread.name
            try:
                thread.join(timeout=2.0)  # Use timeout

                if thread.is_alive():  # Informative messages about thread status
                    self._print(
                        f"{thread_name} did not exit within timeout.", color="yellow"
                    )

                else:
                    self._print(f"{thread_name} exited normally.", color="green")

            except Exception as join_error:  # Handle any exceptions during join.
                self._print(f"Error joining {thread_name}: {join_error}", color="red")

        self.printer.stop()  # Stop pretty printing and print final version of the table

        try:
            self._remove_bridge()
        except Exception as e:
            self._print(f"Error removing bridge: {str(e)}", color="red")

        try:  # Restore interface
            subprocess.run(
                ["ip", "link", "set", self.interface_name, "up"],
                check=True,
                capture_output=True,
                text=True,
            )
            self._print(f"Interface {self.interface_name} set up.", color="green")

        except (
            subprocess.SubprocessError
        ) as iface_error:  # Handle any subprocess errors.
            self._print(
                f"Error setting up interface {self.interface_name}: {str(iface_error)}",
                color="red",
            )
            if self.verbose:
                self.console.print_exception()  # Show full error if verbose is enabled

        self._update_status("[bold red]Stopped[/]")  # Final status update to the table

        self._print("Rerouting stopped.", color="green")

    def _update_status(self, status):
        """Dynamically determines the 'Status' row index for updating."""

        # Find the index of the "Status" row
        status_row_index = None
        for i, row in enumerate(self.printer.table.rows):
            if str(row.header) == "Status":  # Find "Status" row.
                status_row_index = i
                break

        if status_row_index is not None:
            self.update_queue.put(
                ("update_cell", status_row_index, 1, status)
            )  # Correct usage of update_queue

        else:  # If the "Status" row is somehow not in the table.
            self.console.print(
                "[bold yellow]Warning: 'Status' row not found in PrettyPrint table/]"
            )


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
