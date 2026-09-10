"""
Simple logging utility for the DAST framework.
"""

import sys
from datetime import datetime


class Logger:
    """Simple logger with colored output for terminal."""

    COLORS = {
        "INFO": "\033[94m",     # Blue
        "SUCCESS": "\033[92m",  # Green
        "WARNING": "\033[93m",  # Yellow
        "ERROR": "\033[91m",    # Red
        "RESET": "\033[0m",
    }

    @staticmethod
    def _log(level, message):
        color = Logger.COLORS.get(level, "")
        reset = Logger.COLORS["RESET"]
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{color}[{timestamp}] [{level}] {message}{reset}", file=sys.stderr)

    @staticmethod
    def info(message):
        Logger._log("INFO", message)

    @staticmethod
    def success(message):
        Logger._log("SUCCESS", message)

    @staticmethod
    def warning(message):
        Logger._log("WARNING", message)

    @staticmethod
    def error(message):
        Logger._log("ERROR", message)
