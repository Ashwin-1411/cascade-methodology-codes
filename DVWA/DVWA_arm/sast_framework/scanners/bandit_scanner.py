import json
from sast_framework.utils.runner import run_command


def run_bandit(target):
    """Run Bandit SAST scanner on Python code."""
    cmd = ["python3", "-m", "bandit", "-r", target, "-f", "json", "-q"]
    output = run_command(cmd)

    if not output:
        return []

    try:
        data = json.loads(output)
        return data.get("results", [])
    except json.JSONDecodeError:
        return []
