import csv
import io
from sast_framework.utils.runner import run_command


def run_flawfinder(target):
    """Run Flawfinder SAST scanner on C/C++ code."""
    cmd = ["python3", "-m", "flawfinder", "--csv", target]
    output = run_command(cmd)

    if not output:
        return []

    findings = []
    try:
        f = io.StringIO(output)
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('File'):
                findings.append({
                    "file": row.get("File"),
                    "line": row.get("Line"),
                    "name": row.get("Name"),
                    "message": f"{row.get('Warning', '')} - {row.get('Suggestion', '')}",
                    "level": row.get("Level"),
                    "cwe": row.get("CWEs")
                })
    except Exception as e:
        print(f"[!] Error parsing flawfinder CSV: {e}")

    return findings
