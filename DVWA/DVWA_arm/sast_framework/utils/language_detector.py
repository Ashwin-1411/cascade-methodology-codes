# utils/language_detector.py

import subprocess
import os
import shutil


# Map enry language names to our internal scanner categories
LANGUAGE_MAP = {
    "Python": "python",
    "C": "c_cpp",
    "C++": "c_cpp",
    "C#": "csharp",
    "Java": "java",
    "JavaScript": "javascript",
    "TypeScript": "typescript",
    "Go": "go",
    "Ruby": "ruby",
    "PHP": "php",
    "Rust": "rust",
    "Shell": "shell",
    "Kotlin": "kotlin",
    "Swift": "swift",
    "Scala": "scala",
}


def _find_enry():
    """Find the enry binary, checking common locations."""
    # Check if enry is in PATH
    enry_path = shutil.which("enry")
    if enry_path:
        return enry_path

    # Check common install locations
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, ".local", "bin", "enry"),
        "/usr/local/bin/enry",
        "/usr/bin/enry",
    ]
    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    return None


def detect_languages(target_path):
    """
    Detect programming languages in a project directory using enry.

    Enry default output format (no flags):
        <percentage>\t<language>
        e.g.:
        52.00%\tPython
        30.50%\tJavaScript
        17.50%\tHTML

    Returns:
        List of internal language identifiers (e.g. ['python', 'java', 'c_cpp'])
    """
    enry_bin = _find_enry()
    if not enry_bin:
        print("[!] enry binary not found. Cannot detect languages.")
        print("    Install enry: go install github.com/go-enry/enry/v2/cmd/enry@latest")
        return []

    try:
        abs_target = os.path.abspath(target_path)
        if not os.path.isdir(abs_target):
            print(f"[!] Target path does not exist: {abs_target}")
            return []

        result = subprocess.run(
            [enry_bin, abs_target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=120
        )

        if result.returncode != 0 and result.stderr:
            print(f"[!] enry stderr: {result.stderr.strip()}")

        detected = set()

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            # Enry output format: "<percentage>\t<language>"
            # e.g. "52.00%\tPython"
            if "\t" in line:
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    lang = parts[1].strip()
                else:
                    continue
            else:
                # Fallback: try space-separated (last token)
                parts = line.split()
                lang = parts[-1] if parts else ""

            if lang in LANGUAGE_MAP:
                detected.add(LANGUAGE_MAP[lang])

        return list(detected)

    except subprocess.TimeoutExpired:
        print("[!] Language detection timed out")
        return []
    except Exception as e:
        print(f"[!] Language detection failed: {e}")
        return []