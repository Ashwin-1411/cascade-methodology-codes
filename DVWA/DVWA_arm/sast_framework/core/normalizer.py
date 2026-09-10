# core/normalizer.py

from sast_framework.core.schema import Vulnerability, normalize_severity


def normalize_results(raw_results):
    normalized = []

    # Bandit
    for issue in raw_results.get("bandit", []):
        vuln = Vulnerability(
            file=issue.get("filename"),
            line=issue.get("line_number"),
            vulnerability=issue.get("test_name"),
            why=issue.get("issue_text"),
            remediation="Review code and follow secure coding practices",
            cwe=issue.get("issue_cwe", {}).get("id") if issue.get("issue_cwe") else None,
            severity=normalize_severity(issue.get("issue_severity")),
            scanner="bandit",
            language="python"
        )
        normalized.append(vuln.to_dict())

    # Flawfinder
    for issue in raw_results.get("flawfinder", []):
        vuln = Vulnerability(
            file=issue.get("file"),
            line=issue.get("line"),
            vulnerability=issue.get("name"),
            why=issue.get("message"),
            remediation="Use safer alternatives or input validation",
            cwe=issue.get("cwe"),
            severity=normalize_severity(issue.get("level")),
            scanner="flawfinder",
            language="c_cpp"
        )
        normalized.append(vuln.to_dict())

    # SpotBugs
    for issue in raw_results.get("spotbugs", []):
        vuln = Vulnerability(
            file=issue.get("file"),
            line=issue.get("line"),
            vulnerability=issue.get("type") or issue.get("category"),
            why=issue.get("message"),
            remediation="Refactor according to SpotBugs recommendation",
            cwe=issue.get("cwe"),
            severity=normalize_severity(issue.get("priority")),
            scanner="spotbugs",
            language="java"
        )
        normalized.append(vuln.to_dict())

    # Semgrep — PHP, JavaScript, Python (OWASP Top 10 rules)
    for issue in raw_results.get("semgrep", []):
        vuln = Vulnerability(
            file=issue.get("file_path", issue.get("file", "")),
            line=issue.get("line", 0),
            vulnerability=issue.get("vulnerability", issue.get("check_id", "semgrep-finding")),
            why=issue.get("message", ""),
            remediation="Apply input validation and use parameterised queries / safe APIs",
            cwe=issue.get("cwe"),
            severity=issue.get("severity", "Medium"),
            scanner="semgrep",
            language=issue.get("language", "php"),
        )
        d = vuln.to_dict()
        d["tool"] = "semgrep"
        normalized.append(d)

    return normalized