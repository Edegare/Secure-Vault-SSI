import os
import sys
import inspect
from datetime import datetime
from enum import Enum
from typing import Tuple


class LOG_LEVEL(Enum):
    INFO = 0
    VERBOSE = 1


class PREFIX_SUFFIX:
    INFO = '\033[94m'
    SUCCESS = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    ENDC = '\033[0m'


class Logger:
    def __init__(self, file_path: str, show_output: bool, level: LOG_LEVEL):
        self.file_path = file_path
        # create a header to distinguish server runs
        with open(self.file_path, "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"""\n\n\n================================\nServer run on {
                    timestamp}\n================================\n\n""")
        self.show_output = show_output
        self.level = LOG_LEVEL(level) if isinstance(level, int) else level
        self.display_colors = self._can_display_colors()

    # private func
    def _can_display_colors(self) -> bool:
        """Returns True if the terminal supports color, otherwise False."""
        if sys.stdout.isatty() and "TERM" in os.environ:
            term = os.environ["TERM"]
            # Checking for common terms that support colors
            if "color" in term or "xterm" in term or "screen" in term:
                return True
        return False

    # private func
    def _get_call_context(self) -> str:
        """Returns timestamp, file, line, and function."""
        frame = inspect.currentframe()
        if frame is None:
            return ""

        # move back 3 frames: _get_call_context -> _print -> public method (info/warn/...)
        f1 = frame.f_back
        if f1 is None:
            return ""

        f2 = f1.f_back
        if f2 is None:
            return ""

        outer_frame = f2.f_back
        if outer_frame is None:
            return ""

        filename = os.path.basename(inspect.getfile(outer_frame))
        lineno = outer_frame.f_lineno
        funcname = outer_frame.f_code.co_name

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"[{timestamp}] {filename}:{funcname}:{lineno}"

    # private func
    def _print(self, message: str, message_verbose: str,
               prefix_suffix: Tuple[str, str, str]) -> None:
        prefix, type, suffix = prefix_suffix

        if self.level == LOG_LEVEL.INFO:
            message_to_print = message
        else:
            context = self._get_call_context()
            message_to_print = f"{context} - {message_verbose}"

        with open(self.file_path, "a") as f:
            f.write(f"{type}{message_to_print}\n")

        if self.show_output:
            print(f"{prefix}{type}{message_to_print}{suffix}")

    def print(self, message: str, message_verbose: str) -> None:
        self._print(message, message_verbose,
                    ("", "", ""))

    def success(self, message: str, message_verbose: str) -> None:
        if self.display_colors:
            self._print(message, message_verbose,
                        (PREFIX_SUFFIX.SUCCESS, "[SUCCESS] ", PREFIX_SUFFIX.ENDC))
        else:
            self._print(message, message_verbose,
                        ("", "[SUCCESS] ", ""))

    def info(self, message: str, message_verbose: str) -> None:
        if self.display_colors:
            self._print(message, message_verbose,
                        (PREFIX_SUFFIX.INFO, "[INFO] ", PREFIX_SUFFIX.ENDC))
        else:
            self._print(message, message_verbose,
                        ("", "[INFO] ", ""))

    def warn(self, message: str, message_verbose: str) -> None:
        if self.display_colors:
            self._print(message, message_verbose,
                        (PREFIX_SUFFIX.WARNING, "[WARNING] ", PREFIX_SUFFIX.ENDC))
        else:
            self._print(message, message_verbose,
                        ("", "[WARNING] ", ""))

    def error(self, message: str, message_verbose: str) -> None:
        if self.display_colors:
            self._print(message, message_verbose,
                        (PREFIX_SUFFIX.ERROR, "[ERROR] ", PREFIX_SUFFIX.ENDC))
        else:
            self._print(message, message_verbose,
                        ("", "[ERROR] ", ""))
