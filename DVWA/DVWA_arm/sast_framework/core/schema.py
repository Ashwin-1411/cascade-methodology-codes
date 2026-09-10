# core/schema.py

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any


@dataclass
class Vulnerability:
    file: str
    line: Optional[int]
    vulnerability: str
    why: str
    remediation: str
    cwe: Optional[str] = None
    severity: Optional[str] = None
    scanner: Optional[str] = None
    language: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability object to dictionary."""
        return asdict(self)


def normalize_severity(severity: Any) -> Optional[str]:
    """Normalize severity labels across tools."""
    if severity is None:
        return None

    # Handle numeric severities from tools like flawfinder or spotbugs
    if isinstance(severity, int):
        if severity >= 4:
            return "High"
        if severity >= 2:
            return "Medium"
        return "Low"

    severity_str = str(severity).upper()

    mapping = {
        "LOW": "Low",
        "MEDIUM": "Medium",
        "HIGH": "High",
        "CRITICAL": "Critical",
        "INFO": "Low",
        "WARNING": "Medium",
        "ERROR": "High",
        "1": "High",
        "2": "Medium",
        "3": "Low",
        "4": "High",
        "5": "High"
    }

    return mapping.get(severity_str, severity_str.capitalize())