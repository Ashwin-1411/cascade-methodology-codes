# core/orchestrator.py

import os
from sast_framework.scanners.bandit_scanner import run_bandit
from sast_framework.scanners.flawfinder_scanner import run_flawfinder
from sast_framework.scanners.spotbugs_scanner import run_spotbugs
from sast_framework.scanners.semgrep_scanner import run_semgrep
from sast_framework.core.normalizer import normalize_results
from sast_framework.utils.file_utils import save_json
from sast_framework.utils.language_detector import detect_languages


def run_sast(target_path, output_dir):
    """
    Run SAST analysis on the given target path.

    Scanners:
      - Bandit      → Python
      - Flawfinder  → C/C++
      - SpotBugs    → Java
      - Semgrep     → PHP, JavaScript, Python (OWASP Top 10 rules)
                      This is the key scanner for DVWA (which is PHP).
    """
    raw_dir = os.path.join(output_dir, "raw")
    norm_dir = os.path.join(output_dir, "normalized")

    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(norm_dir, exist_ok=True)

    raw_results = {}

    print(f"\n{'='*50}")
    print(f"[*] SAST Scan Target: {target_path}")
    print(f"{'='*50}")

    languages = detect_languages(target_path)
    print(f"[*] Detected languages: {languages}")

    if "python" in languages:
        print("\n[*] Running Bandit (Python SAST)...")
        raw_results["bandit"] = run_bandit(target_path)
        print(f"    Found {len(raw_results['bandit'])} issues")

    if "c_cpp" in languages:
        print("\n[*] Running Flawfinder (C/C++ SAST)...")
        raw_results["flawfinder"] = run_flawfinder(target_path)
        print(f"    Found {len(raw_results['flawfinder'])} issues")

    if "java" in languages:
        print("\n[*] Running SpotBugs (Java SAST)...")
        raw_results["spotbugs"] = run_spotbugs(target_path)
        print(f"    Found {len(raw_results['spotbugs'])} issues")

    # Semgrep covers PHP + JavaScript + Python with OWASP Top 10 rules
    # Critical for DVWA which is primarily PHP
    semgrep_langs = {"php", "javascript", "python", "typescript"}
    if semgrep_langs.intersection(set(languages)):
        print("\n[*] Running Semgrep (PHP/JS/Python OWASP Top 10)...")
        raw_results["semgrep"] = run_semgrep(target_path)
        print(f"    Found {len(raw_results['semgrep'])} issues")
    else:
        # Run semgrep anyway as a catch-all — it auto-detects language
        print("\n[*] Running Semgrep (catch-all OWASP scan)...")
        raw_results["semgrep"] = run_semgrep(target_path)
        print(f"    Found {len(raw_results['semgrep'])} issues")

    # Report fully unsupported languages (those semgrep also can't handle)
    supported = {"python", "c_cpp", "java", "php", "javascript", "typescript"}
    unsupported = set(languages) - supported
    if unsupported:
        print(f"\n[!] No specific scanner for: {unsupported} (Semgrep attempted)")

    if not raw_results:
        print("\n[!] No supported languages detected. No SAST scans were run.")
        return []

    # Save raw results
    raw_output_path = os.path.join(raw_dir, "raw_results.json")
    save_json(raw_output_path, raw_results)
    print(f"\n[*] Raw results saved to: {raw_output_path}")

    # Normalize results
    print("[*] Normalizing results...")
    normalized = normalize_results(raw_results)

    norm_output_path = os.path.join(norm_dir, "normalized_results.json")
    save_json(norm_output_path, normalized)
    print(f"[*] Normalized results saved to: {norm_output_path}")

    # Print summary
    print(f"\n{'='*50}")
    print(f"[+] SAST SCAN COMPLETE")
    print(f"    Total vulnerabilities found: {len(normalized)}")
    for vuln in normalized:
        severity = vuln.get('severity', 'Unknown')
        tool = vuln.get('tool', vuln.get('scanner', 'unknown'))
        print(f"    - [{severity}] [{tool}] {vuln.get('vulnerability', 'N/A')} "
              f"in {vuln.get('file', 'N/A')}:{vuln.get('line', '?')}")
    print(f"{'='*50}")

    return normalized
