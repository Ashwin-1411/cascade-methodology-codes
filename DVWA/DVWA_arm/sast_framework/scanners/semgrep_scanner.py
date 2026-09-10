"""
Semgrep SAST scanner — supports PHP, JavaScript, Python, and more.

Fills the gap where Bandit only covers Python but DVWA is PHP.
Uses p/php + p/owasp-top-ten rulesets.

v2: Added CWE fallback table for semgrep rules that don't include
CWE metadata. This ensures injection findings map correctly to
A03 in coverage analysis even without explicit CWE numbers.
"""

import json
import shutil
import subprocess


# ---------------------------------------------------------------------------
# CWE fallback: semgrep rule ID patterns → CWE number
# Used when semgrep metadata doesn't include cwe-id
# ---------------------------------------------------------------------------
_RULE_TO_CWE: dict[str, int] = {
    "tainted-sql":           89,   # SQL Injection
    "sql-injection":         89,
    "tainted-exec":          78,   # OS Command Injection
    "exec-injection":        78,
    "command-injection":     78,
    "tainted-filename":      22,   # Path Traversal / LFI
    "path-traversal":        22,
    "file-inclusion":        98,
    "echoed-request":        79,   # XSS
    "tainted-html":          79,
    "xss":                   79,
    "cross-site-scripting":  79,
    "open-redirect":         601,
    "csrf":                  352,
    "phpinfo":               200,  # Info Disclosure
    "hardcoded":             798,  # Hardcoded credentials
    "weak-crypto":           327,
    "insecure-deserialization": 502,
    "xxe":                   611,
    "ssrf":                  918,
    "upload":                434,  # Unrestricted upload
}


def _infer_cwe_from_rule(rule_id: str, vuln_name: str) -> int | None:
    """Infer CWE from rule ID or vulnerability name when metadata lacks it."""
    combined = (rule_id + " " + vuln_name).lower().replace(" ", "-")
    for pattern, cwe in _RULE_TO_CWE.items():
        if pattern in combined:
            return cwe
    return None


def run_semgrep(target: str) -> list:
    """
    Run Semgrep on the target directory with PHP + OWASP Top 10 rulesets.
    Returns list of findings in normaliser-compatible format.
    """
    if not shutil.which("semgrep"):
        print("    [!] semgrep not found. Install with: pip install semgrep")
        return []

    result = subprocess.run(
        [
            "semgrep",
            "--config", "p/php",
            "--config", "p/owasp-top-ten",
            "--config", "p/javascript",
            "--json",
            "--quiet",
            "--no-git-ignore",
            target,
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )

    findings = []
    try:
        raw_text = result.stdout or ""
        if not raw_text.strip():
            return []
        data = json.loads(raw_text)

        for item in data.get("results", []):
            meta     = item.get("extra", {})
            metadata = meta.get("metadata", {})
            rule_id  = item.get("check_id", "")

            # Severity mapping
            sev_map = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}
            severity = sev_map.get(meta.get("severity", "WARNING"), "Medium")

            # Vuln name: use last segment of rule ID, cleaned up
            rule_short = rule_id.split(".")[-1].replace("-", " ").title()
            vuln_name = rule_short

            # CWE: try metadata first, then fallback table
            cwe = None
            cwe_list = metadata.get("cwe", [])
            if isinstance(cwe_list, str):
                cwe_list = [cwe_list]
            if cwe_list:
                try:
                    cwe = int(str(cwe_list[0]).split("-")[-1])
                except (ValueError, TypeError):
                    pass
            if not cwe:
                cwe = _infer_cwe_from_rule(rule_id, vuln_name)

            findings.append({
                "tool":          "semgrep",
                "check_id":      rule_id,
                "vulnerability": vuln_name,
                "severity":      severity,
                "file":          item.get("path", ""),
                "file_path":     item.get("path", ""),
                "line":          item.get("start", {}).get("line", 0),
                "col":           item.get("start", {}).get("col", 0),
                "message":       meta.get("message", ""),
                "cwe":           cwe,
                "scan_type":     "SAST",
                "confidence":    metadata.get("confidence", "MEDIUM"),
            })
    except (json.JSONDecodeError, Exception) as e:
        print(f"    [!] Error parsing semgrep output: {e}")

    return findings