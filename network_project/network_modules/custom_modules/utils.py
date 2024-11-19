#!/usr/bin/python3

import logging
import random
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.style import Style
from rich.text import Text
from rich.logging import RichHandler
from typing import Optional, List, Dict, Any
from collections import OrderedDict

# Configure Rich logging handler (optional, but recommended)
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)],  # For colorful tracebacks
)
log = logging.getLogger("rich")


class TextColors:
    # ANSI escape codes for text coloring (can be expanded)
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


class Utils:
    console = Console()  # Rich console object.

    @staticmethod
    def pretty_print(
        data: Any,
        title: str = "Output",
        style: str = "default",
        justify: str = "left",
        width: Optional[int] = None,
        as_table: bool = True,
        table_title: str = "Results",
    ) -> None:

        styles = {
            "default": Style(color="white"),
            "info": Style(color="cyan"),
            "success": Style(color="green"),
            "warning": Style(color="yellow"),
            "error": Style(color="red"),
            "critical": Style(color="bold red", blink=True, underline=True),
        }

        chosen_style = styles.get(style, styles["default"])

        if as_table:  # Print data within a formatted table.
            if isinstance(data, dict) or isinstance(data, OrderedDict):
                table = Table(
                    title=table_title, show_header=True, header_style="bold magenta"
                )

                if isinstance(data, OrderedDict):  # Handles OrderedDicts
                    for key in data.keys():
                        table.add_column(
                            str(key).title(), justify=justify, style=chosen_style
                        )
                    table.add_row(*[str(value) for value in data.values()])

                elif isinstance(data, dict):  # Handles regular dictionaries
                    if data:
                        first_key = list(data.keys())[0]
                        if isinstance(
                            data[first_key], list
                        ):  # For lists of dictionaries
                            for key in data[first_key][0]:
                                table.add_column(
                                    str(key).title(),
                                    justify=justify,
                                    style=chosen_style,
                                )
                            for row in data[first_key]:
                                if row:
                                    table.add_row(
                                        *[str(value) for value in row.values()]
                                    )

                        else:  # For regular dict
                            for key in data:
                                table.add_column(
                                    str(key).title(),
                                    justify=justify,
                                    style=chosen_style,
                                )
                            if data:
                                table.add_row(*[str(value) for value in data.values()])

                Utils.console.print(table)

            elif isinstance(data, list):
                if data and isinstance(data[0], dict):  # if it is a list of dict
                    table = Table(
                        title=table_title, show_header=True, header_style="bold magenta"
                    )
                    for key in data[0]:  # add columns from dict keys
                        table.add_column(
                            str(key).title(), justify=justify, style=chosen_style
                        )
                    for item in data:  # add rows from list items
                        if item:
                            table.add_row(*[str(value) for value in item.values()])
                    Utils.console.print(table)

                elif not isinstance(data[0], dict) and data:  # list of items, not dicts
                    table = Table(title=table_title, show_lines=True, show_header=False)
                    table.add_column("Items", justify=justify, style=chosen_style)
                    for item in data:
                        table.add_row(str(item))
                    Utils.console.print(table)

                else:
                    Utils.pretty_print(
                        message=f"No data to print or invalid data type for a table {data}",
                        style="warning",
                    )

        else:  # Display string, list, tuple, etc. as text output
            if isinstance(data, (list, tuple, set)):
                text = Text(
                    "\n".join([str(item) for item in data]),
                    style=chosen_style,
                    justify=justify,
                )

            elif isinstance(data, dict) or isinstance(
                data, OrderedDict
            ):  # Improved dict printing
                text_parts = [
                    Text(f"[bold]{key.title()}[/]: ", style=chosen_style)
                    + Text(str(value), style="white")
                    for key, value in data.items()
                ]
                text = Text("\n").join(text_parts)

            elif isinstance(data, str):  # For single string messages
                text = Text(data, style=chosen_style, justify=justify)

            else:
                text = Text(
                    repr(data), style=chosen_style, justify=justify
                )  # Display repr if not recognized.

            Utils.console.print(
                Panel(
                    text,
                    title=title,
                    title_align="left",
                    width=width,
                    border_style="dim",
                    expand=True,
                )
            )

    @staticmethod
    def print_status(
        message: str, level="info"
    ) -> None:  # Enhanced log output using pretty_print
        Utils.pretty_print(message, title=f"[bold]{level.upper()}[/]", style=level)

    @staticmethod
    def generate_random_data(
        num_items: int = 10, data_type: str = "str"
    ) -> List[Any]:  # Utility function to create random data
        if data_type == "str":
            return [
                "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for i in range(8))
                for _ in range(num_items)
            ]
        elif data_type == "int":
            return [random.randint(1, 100) for _ in range(num_items)]
        elif data_type == "dict":
            return [
                {
                    "name": "".join(
                        random.choice("abcdefghijklmnopqrstuvwxyz") for i in range(5)
                    ),
                    "value": random.randint(1, 1000),
                }
                for _ in range(num_items)
            ]
        else:
            return [
                "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for i in range(8))
                for _ in range(num_items)
            ]  # Default to str if not recognized
