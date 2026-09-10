"""
main.py
--------
CLI entry point for the DAST framework.
Accepts GitHub URL or local path and initiates scan pipeline.

Usage:
    python3 main.py <github_repo_url | local_project_path>
"""

import sys
import os
import json
import time

# Add framework root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dast_framework.core.input_handler import acquire_source
from dast_framework.core.docker_runner import build_and_run
from dast_framework.core.orchestrator import run_dast
from dast_framework.core.cleanup import cleanup_resources


def write_report(findings, output_dir):
    """Write findings to a timestamped JSON report file."""
    reports_dir = os.path.join(output_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    filename = f"dast_report_{int(time.time())}.json"
    path = os.path.join(reports_dir, filename)

    with open(path, "w") as f:
        json.dump(findings, f, indent=2)

    return path


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <github_repo_url | local_project_path>")
        sys.exit(1)

    source = sys.argv[1]
    container_id = None
    repo_path = None
    cloned = False

    try:
        repo_path, cloned = acquire_source(source)

        print(f"\n{'='*50}")
        print(f"[*] DAST Scan Target: {repo_path}")
        print(f"{'='*50}")

        print("\n[*] Building and starting target application in Docker...")
        runtime = build_and_run(repo_path)
        container_id = runtime["container_id"]

        print(f"[*] Target running at: {runtime['host_url']}")
        print("[*] Running DAST scanners...\n")

        findings = run_dast(runtime)

        # Write report
        framework_dir = os.path.dirname(os.path.abspath(__file__))
        output_dir = os.path.join(framework_dir, "output")
        report_path = write_report(findings, output_dir)

        # Print summary
        print(f"\n{'='*50}")
        print(f"[+] DAST SCAN COMPLETE")
        print(f"    Total findings: {len(findings)}")
        print(f"    Report saved to: {report_path}")
        for f_item in findings:
            tool = f_item.get('tool', 'unknown')
            vuln = f_item.get('vulnerability', f_item.get('type', 'N/A'))
            endpoint = f_item.get('endpoint', 'N/A')
            print(f"    - [{tool}] {vuln} at {endpoint}")
        print(f"{'='*50}")

    except FileNotFoundError:
        print("[!] Docker not found. DAST requires Docker to be installed and running.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] DAST scan error: {e}")
        sys.exit(1)
    finally:
        cleanup_resources(container_id, repo_path, cloned)


if __name__ == "__main__":
    main()
