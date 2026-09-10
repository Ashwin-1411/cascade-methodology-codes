"""
main.py
--------
CLI entry point for the SAST framework.
Accepts GitHub URL or local path and initiates SAST scan pipeline.

Usage:
    python3 main.py <github_repo_url | local_project_path>
"""

import sys
import os
import shutil

# Add framework root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sast_framework.core.input_handler import acquire_source
from sast_framework.core.orchestrator import run_sast


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <github_repo_url | local_project_path>")
        sys.exit(1)

    source = sys.argv[1]
    target_path = None
    cloned = False

    try:
        target_path, cloned = acquire_source(source)

        # Output directory inside the sast_framework folder
        framework_dir = os.path.dirname(os.path.abspath(__file__))
        output_dir = os.path.join(framework_dir, "output")

        run_sast(target_path, output_dir)

    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    finally:
        if cloned and target_path and os.path.exists(target_path):
            print(f"[*] Cleaning up cloned repository: {target_path}")
            shutil.rmtree(target_path, ignore_errors=True)


if __name__ == "__main__":
    main()