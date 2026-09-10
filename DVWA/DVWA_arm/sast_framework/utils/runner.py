import subprocess
import json


def run_command(cmd):
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        return result.stdout
    except Exception as e:
        print(f"Error running command: {e}")
        return None