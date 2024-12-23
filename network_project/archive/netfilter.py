#!/usr/bin/python3

"""How to Use:

Instantiate: Create an instance of the Netfilter class, optionally providing a queue number and a callback function.

iptables Rule: Use iptables to direct traffic to the specified queue number. For example:

sudo iptables -I INPUT -j NFQUEUE --queue-num <your_queue_number>
Run: Call the run() method to start the packet processing loop.

Callback: The provided callback function will be executed for each intercepted packet. The payload can be modified, and a verdict (e.g., NF_ACCEPT, NF_DROP, NF_MODIFY) needs to be set.

Stop: Call the stop() method to terminate the processing loop.
"""

import nfqueue
import socket
import logging
from scapy.all import *

# Configure logging (adjust level and format as needed)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class Netfilter:  # One-worded, robust, and technical
    """Integrates with NFQUEUE to intercept and modify network packets."""

    def __init__(self, queue_num=0, callback=None):
        """Initializes the Netfilter object."""
        self.logger = logging.getLogger(__name__)
        self.queue_num = queue_num
        self.callback = (
            callback or self._default_callback
        )  # Use default if no callback provided
        self.nfqueue_instance = None  # Store the nfqueue instance

    def _default_callback(self, i, payload):  # Default callback action
        """Default callback function if none is provided by the user."""
        data = payload.get_data()
        pkt = IP(data)
        self.logger.info(f"Received packet: {pkt.summary()}")
        payload.set_verdict(nfqueue.NF_ACCEPT)

    def run(self):
        """Starts the NFQUEUE processing loop."""
        try:
            self.nfqueue_instance = nfqueue.queue()
            self.nfqueue_instance.set_callback(self.callback)
            self.nfqueue_instance.fast_open(
                self.queue_num, socket.AF_INET
            )  # Use specified queue number

            self.logger.info(f"Started NFQUEUE on queue {self.queue_num}")
            self.nfqueue_instance.try_run()  # Start processing packets

        except nfqueue.NFError as e:  # Handle nfqueue-specific exceptions
            self.logger.error(f"NFQUEUE error: {e}")

        except (OSError, socket.error) as e:  # Handle socket-related errors
            self.logger.error(f"Error opening NFQUEUE socket: {e}")
        finally:  # Ensure nfqueue close for cleanup, even with exceptions

            if self.nfqueue_instance:
                self.nfqueue_instance.unbind()
                self.nfqueue_instance.close()

    def stop(self):
        """Stops the NFQUEUE processing loop."""
        if self.nfqueue_instance:
            self.nfqueue_instance.unbind()  # unbind from queue
            self.nfqueue_instance.close()
            self.logger.info("Stopped NFQUEUE")

    def set_callback(self, callback):
        """Sets the callback function to be executed for each packet."""
        self.callback = callback
