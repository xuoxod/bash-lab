# prettyprint.py (Revised)
from rich.console import Console
from rich.table import Table


class PrettyPrint:
    def __init__(self, title="Status"):
        self.console = Console()
        self.table = Table(title=title, show_lines=True)

    def add_column(self, header, style="green", no_wrap=True):
        self.table.add_column(header, style=style, no_wrap=no_wrap)

    def add_row(self, *row_data):
        self.table.add_row(*row_data)

    def update_cell(self, row_index, column_index, value):
        self.table.rows[row_index].cells[column_index] = str(value)  #Force string conversion.

    def print_table(self):  #Prints current table to the console.
       self.console.print(self.table)

#In rerouter.py

#In __init__():
     self.printer = PrettyPrint(title="Rerouter Status")
     self.update_queue = Queue()  # Create a queue for updates.


# ... other methods

def start(self):
    # ... existing code
    #Before starting the while True loop:
    self.pretty_print_thread = threading.Thread(target=self._pretty_print_loop, daemon=True) # New print thread.
    self.pretty_print_thread.start()


    self.printer.add_column("Field", style="cyan")
    self.printer.add_column("Value", style="magenta")


    # Add initial data (call from start).
    self._add_table_row("Target IP", self.target_ip)
    self._add_table_row("Target MAC", self.target_mac)
    # ... Add other initial fields.


    while True: # ... (Rest of your loop)


def _add_table_row(self, field, value): #Helper to add initial rows from start()
    self.update_queue.put(
         ("add_row", field, value)
    )


def _pretty_print_loop(self):
     while True:
        try:
            action, *args = self.update_queue.get()
            if action == "add_row":
                self.printer.add_row(*args) # Safely add rows in main thread
            elif action == "update_cell":
                self.printer.update_cell(*args)  # Safely update in main thread

            self.printer.print_table() #Update the display

        except Exception as e:
            self._print(f"[bold red]Error in pretty print loop: {e}[/]")
            if self.verbose:
                self.console.print_exception()


def stop(self):
    # ... existing code ...
    if hasattr(self, "pretty_print_thread"):
       self.update_queue.put(None) # Signal to stop pretty print thread
       self.pretty_print_thread.join(timeout=2.0) # Wait for thread to finish


# Example of how to update a field from another thread (like _forward_traffic):
self.update_queue.put(("update_cell", 0, 1, "New Value"))  # Assuming 'Status' is at row 0, column 1



