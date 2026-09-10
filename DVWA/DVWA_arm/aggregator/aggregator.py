"""
aggregator.py
-------------
Aggregates SAST and DAST findings into a single structured JSON report.

Output order:
  1. Matched findings  – same CWE *and* overlapping file/endpoint path
  2. Unmatched SAST    – SAST findings with no DAST counterpart
  3. Unmatched DAST    – DAST findings with no SAST counterpart

Inputs are always read directly from:
  - sast_framework/output/normalized/normalized_results.json
  - dast_framework/output/reports/dast_report_*.json  (latest file)
"""

import glob
import json
import os
import re


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_sast_findings(base_dir: str) -> list:
    path = os.path.join(base_dir, "sast_framework", "output", "normalized", "normalized_results.json")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)


def load_dast_findings(base_dir: str) -> list:
    reports_dir = os.path.join(base_dir, "dast_framework", "output", "reports")
    if not os.path.exists(reports_dir):
        return []
    files = glob.glob(os.path.join(reports_dir, "dast_report_*.json"))
    if not files:
        return []
    latest = max(files, key=os.path.getmtime)
    with open(latest) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------

# Segments too generic to be useful for path-based matching
_SKIP_SEGMENTS = {
    "php", "html", "js", "index", "source", "low", "medium", "high",
    "impossible", "home", "usr", "var", "www", "src", "include",
    "includes", "dvwa", "config", "lib", "class", "ids", "view",
}


def _normalize_cwe(val) -> int | None:
    if val is None:
        return None
    try:
        return int(re.sub(r"(?i)cwe-?", "", str(val)).strip())
    except (ValueError, AttributeError):
        return None


def _path_segments(raw: str) -> set:
    """Return meaningful lowercase path segments from a file path or URL."""
    if not raw:
        return set()
    # Strip protocol + host from URLs
    cleaned = re.sub(r"^https?://[^/]+", "", str(raw))
    # Split on common separators
    parts = re.split(r"[/\\?&=#+.]", cleaned)
    return {p.lower() for p in parts if p and p.lower() not in _SKIP_SEGMENTS}


def _paths_overlap(sast_file: str, dast_url: str) -> bool:
    """True when the two paths share at least one meaningful segment."""
    sast_segs = _path_segments(sast_file)
    dast_segs = _path_segments(dast_url)
    if not sast_segs or not dast_segs:
        return False
    return bool(sast_segs & dast_segs)


def _dast_cwe(df: dict) -> int | None:
    """Extract CWE from a DAST finding regardless of tool format."""
    # ZAP uses 'cweid', nuclei may use 'cwe' or nested 'info.classification.cwe-id'
    for key in ("cweid", "cwe"):
        val = df.get(key)
        if val:
            if isinstance(val, list):
                val = val[0]
            result = _normalize_cwe(val)
            if result:
                return result
    # Nuclei nested path
    try:
        cwe_list = df["info"]["classification"]["cwe-id"]
        if cwe_list:
            return _normalize_cwe(cwe_list[0])
    except (KeyError, TypeError, IndexError):
        pass
    return None


def _dast_url(df: dict) -> str:
    return df.get("url") or df.get("endpoint") or ""


# ---------------------------------------------------------------------------
# Core aggregator
# ---------------------------------------------------------------------------

def aggregate_findings(sast_findings: list, dast_findings: list) -> dict:
    """
    Match SAST and DAST findings that share the same CWE *and* overlapping
    file/endpoint path.  Returns a dict with a summary block and an ordered
    findings list: matched → unmatched SAST → unmatched DAST.
    """
    matched = []
    sast_used: set[int] = set()
    dast_used: set[int] = set()

    for si, sf in enumerate(sast_findings):
        sast_cwe = _normalize_cwe(sf.get("cwe"))
        sast_file = sf.get("file", "")

        for di, df in enumerate(dast_findings):
            if di in dast_used:
                continue

            dast_cwe = _dast_cwe(df)
            dast_url = _dast_url(df)

            cwe_match = bool(sast_cwe and dast_cwe and sast_cwe == dast_cwe)
            path_match = _paths_overlap(sast_file, dast_url)

            if cwe_match and path_match:
                matched.append({
                    "match_type": "sast_dast_correlated",
                    "cwe": sast_cwe,
                    "severity": sf.get("severity") or df.get("severity", "Unknown"),
                    "vulnerability": sf.get("vulnerability") or df.get("vulnerability", "Unknown"),
                    "file": sast_file,
                    "endpoint": dast_url,
                    "sast": sf,
                    "dast": df,
                })
                sast_used.add(si)
                dast_used.add(di)
                break  # one DAST match per SAST finding is enough

    unmatched_sast = [
        {"match_type": "sast_only", **sf}
        for si, sf in enumerate(sast_findings)
        if si not in sast_used
    ]

    unmatched_dast = [
        {"match_type": "dast_only", "severity": "unknown", **df}
        for di, df in enumerate(dast_findings)
        if di not in dast_used
    ]

    return {
        "summary": {
            "total": len(matched) + len(unmatched_sast) + len(unmatched_dast),
            "correlated": len(matched),
            "sast_only": len(unmatched_sast),
            "dast_only": len(unmatched_dast),
        },
        "findings": matched + unmatched_sast + unmatched_dast,
    }
