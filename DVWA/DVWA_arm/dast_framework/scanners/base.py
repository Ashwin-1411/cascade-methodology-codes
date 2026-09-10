"""
Defines the scanner interface.
All DAST scanners must follow this contract.
"""

from abc import ABC, abstractmethod


class Scanner(ABC):
    name = "base"

    @abstractmethod
    def run(self, target_url, output_dir="."):
        """Execute the scan against the target URL."""
        pass

    @abstractmethod
    def parse_results(self, output_dir="."):
        """Return normalized findings."""
        pass
