# utils/file_utils.py

import json


def load_config(path):
    """Load JSON configuration file."""
    with open(path, "r") as f:
        return json.load(f)


def save_json(path, data):
    """Save data to JSON file."""
    with open(path, "w") as f:
        json.dump(data, f, indent=4)