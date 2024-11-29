from rich.console import Console
from rich.table import Table


class PrettyPrint:  # Enhanced PrettyPrint class with very basic pagination
    def __init__(self, title="", page_size=10):
        self.console = Console()
        self.title = title
        self.rows = []
        self.page_size = page_size
        self.current_page = 0

    def add_column(self, header, style=None, no_wrap=False):
        # Store header for later table creation
        if not hasattr(self, "headers"):
            self.headers = []
        self.headers.append((header, style))

    def add_row(self, *cols):
        self.rows.append(cols)

    def update_cell(self, row, col, value):
        try:
            self.rows[row][col] = value
        except IndexError:
            pass  # Ignore updates for invalid indices

    def print_page(self):  # New method to print a specific page
        start = self.current_page * self.page_size
        end = min((self.current_page + 1) * self.page_size, len(self.rows))

        table = Table(title=self.title)
        for header, style in self.headers:  # Add headers with styling
            table.add_column(header, style=style)

        for row in self.rows[start:end]:
            table.add_row(*row)

        self.console.print(table)

        # Display page information
        self.console.print(
            f"Page {self.current_page + 1} of { (len(self.rows) + self.page_size - 1) // self.page_size}"
        )

    def next_page(self):  # New Method
        if (self.current_page + 1) * self.page_size < len(self.rows):
            self.current_page += 1
            self.print_page()

    def prev_page(self):  # New Method
        if self.current_page > 0:
            self.current_page -= 1
            self.print_page()

    def start(self):  # Unchanged - initializes and prints first page.
        self.print_page()

    def stop(self):  # Now prints the current page
        self.print_page()
