#!/usr/bin/python3


# ANSI escape codes for text coloring (can be moved to a separate utils module)
import random


class TextColors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    # Extended color palette (43 total including basic colors)
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright variations
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Background colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"

    # Additional colors (adjust as needed)
    ORANGE = "\033[38;5;208m"  # Example orange
    ORANGERED = "\033[38;5;196m"  # Example orangered
    PINK = "\033[38;5;205m"
    HOTPINK = "\033[38;5;198m"
    PINKYELLOW = "\033[38;5;226m"  # Example pink-yellow
    OFFWHITE = "\033[38;5;255m"  # Example Off-white
    LIGHTBLUE = "\033[38;5;153m"
    LIGHTGREEN = "\033[38;5;118m"
    DEEPGREEN = "\033[38;5;22m"
    DEEPPINK = "\033[38;5;197m"

    # ... Add more color codes as per your preference, up to 256 using 8-bit color.

    @classmethod
    def blink(cls, text, color=None, blink_times=5):  # Class method
        """Prints blinking colored text."""
        if color is None:
            color = random.choice(
                [
                    attr
                    for attr in cls.__dict__
                    if not callable(getattr(cls, attr)) and not attr.startswith("__")
                ]
            )
        blink_code = "\033[5m"  # Blink code
        output = ""
        for _ in range(blink_times):
            output += f"{color}{blink_code}{text}{cls.ENDC}"
        print(output, end="", flush=True)  # Print without newline, flush output
