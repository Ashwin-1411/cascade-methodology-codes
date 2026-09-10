"""
Cleans up Docker containers, networks and temporary files after a scan.
"""

import subprocess
import shutil
from .docker_runner import NETWORK_NAME, CONTAINER_NAME


def cleanup_resources(container_id, repo_path, cloned):
    # Stop and remove the target container (by name is more reliable than ID)
    subprocess.run(
        ["docker", "rm", "-f", CONTAINER_NAME],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Also try by ID in case name lookup fails
    if container_id:
        subprocess.run(
            ["docker", "rm", "-f", container_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    # Remove the scan network (ignore errors — another scan may be running)
    subprocess.run(
        ["docker", "network", "rm", NETWORK_NAME],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Remove cloned repo if needed
    if cloned and repo_path:
        shutil.rmtree(repo_path, ignore_errors=True)