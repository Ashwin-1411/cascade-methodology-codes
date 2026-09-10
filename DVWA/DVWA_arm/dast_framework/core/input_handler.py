"""
Handles input source acquisition.
Supports:
- GitHub repository URLs (http/https/git@)
- Local filesystem paths
"""

import os
import subprocess
import tempfile


def acquire_source(source):
    """
    Determines whether input is a GitHub repo or local directory.
    Clones GitHub repos into a temporary directory.

    Returns:
        (repo_path, cloned_flag)
    """
    if source.startswith("http://") or source.startswith("https://") or source.startswith("git@"):
        temp_dir = tempfile.mkdtemp(prefix="dast_repo_")
        print(f"[*] Cloning repository: {source}")
        subprocess.run(
            ["git", "clone", "--depth", "1", source, temp_dir],
            check=True
        )
        print(f"[*] Cloned to: {temp_dir}")
        return temp_dir, True

    abs_path = os.path.abspath(source)
    if not os.path.isdir(abs_path):
        raise ValueError(f"Invalid path: '{source}' is not a directory or URL")

    return abs_path, False
