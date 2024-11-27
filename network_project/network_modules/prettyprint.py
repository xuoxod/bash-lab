# prettyprint.py
import threading
import time
from queue import Queue, Empty  # Use queue for thread safety
from rich.console import Console
from rich.table import Table
from rich.live import Live


class PrettyPrint:
    def __init__(self, title="Status", refresh_rate=2):  # Reduced refresh rate.
        self.console = Console()
        self.table = Table(title=title, show_lines=True)
        self.queue = Queue()
        self.live = Live(self.table, refresh_per_second=refresh_rate)
        self.lock = threading.Lock()  # Use a lock for thread safety.
        self._stop_event = threading.Event()  # Control printing thread

    def add_column(self, header, style="green", no_wrap=True):
        with self.lock:  # Protect table modification
            self.table.add_column(header, style=style, no_wrap=no_wrap)

    def add_row(self, *row_data):
        with self.lock:
            self.table.add_row(*row_data)  # Protect with Lock

            if self.live:  # Update Live display atomically
                with self.live:  # Atomic update within Live context
                    self.live.update(self.table)

    def update_cell(self, row_index, column_index, value):
        with self.lock:
            try:
                self.table.rows[row_index].cells[column_index] = str(value)
                if self.live:  # Atomic Live update
                    with self.live:  # Atomic update inside Live
                        self.live.update(self.table)
            except IndexError:  # Handle potential out-of-bounds errors.
                self.console.print(
                    f"[bold yellow]Warning: Invalid row or column index for update.[/]"
                )

    def print_table(self):
        with self.lock:  # Only print statically if there is no Live context.
            if not self.live:  # Check before printing
                self.console.print(self.table)

    def start(self):
        if self.live:
            self.live.start()  # Start Live context
            self._stop_event.clear()  # Make sure stop event is not set initially.

            self.print_thread = threading.Thread(
                target=self._print_loop, daemon=True
            )  # Start print loop thread
            self.print_thread.start()  # Start the PrettyPrint update thread.

    def _print_loop(self):  # Loop to handle printing
        while not self._stop_event.is_set():
            try:
                item = self.queue.get(timeout=1)  # Use timeout for responsiveness
                if item is None:  # Signal to stop
                    break

                action, *args = item
                if action == "add_row":
                    self.add_row(*args)
                elif action == "update_cell":
                    self.update_cell(*args)
            except Empty:  # No items in queue within timeout
                pass
            except Exception as e:
                self.console.print(f"[bold red]Error in print loop: {e}[/]")

    def stop(self):
        if self.live:  # Only perform actions if the class has a live table
            self.queue.put(None)  # Signal the printing thread to stop
            self._stop_event.set()  # Set the event to signal stop

            if hasattr(self, "print_thread"):  # Check existence first
                self.print_thread.join(timeout=2.0)  # Timeout to prevent blocking

            self.live.stop()  # Stop live updates.
            self.print_table()  # Print the final static state of the table.

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()  # Correctly stop using new method.
