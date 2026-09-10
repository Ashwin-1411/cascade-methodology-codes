"""
Normalizes DAST scan findings into a unified format.
"""


def normalize_finding(finding):
    """
    Normalize a single DAST finding into a standard schema.

    Returns a dict with keys: tool, type, vulnerability, severity,
    endpoint, confidence, raw.
    """
    return {
        "tool": finding.get("tool", "unknown"),
        "type": finding.get("type", "vulnerability"),
        "vulnerability": finding.get("vulnerability", finding.get("type", "N/A")),
        "severity": finding.get("severity", "unknown"),
        "endpoint": finding.get("endpoint", "N/A"),
        "confidence": finding.get("confidence", "unknown"),
    }


def normalize_findings(findings):
    """Normalize a list of DAST findings."""
    return [normalize_finding(f) for f in findings]
