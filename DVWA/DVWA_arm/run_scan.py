"""
run_scan.py
-----------
Unified CLI entry point for the CVE Scanner Framework.

Usage:
    python3 run_scan.py --all  ./DVWA
    python3 run_scan.py --sast ./DVWA
    python3 run_scan.py --dast ./DVWA
"""

import argparse
import json
import os
import sys
import subprocess
import tempfile
import shutil
import time


# ---------------------------------------------------------------------------
# Source acquisition
# ---------------------------------------------------------------------------

def acquire_source(source):
    if source.startswith(("http://", "https://", "git@")):
        temp_dir = tempfile.mkdtemp(prefix="scan_repo_")
        print(f"[*] Cloning repository: {source}")
        subprocess.run(["git", "clone", "--depth", "1", source, temp_dir], check=True)
        return temp_dir, True
    abs_path = os.path.abspath(source)
    if not os.path.isdir(abs_path):
        print(f"[!] Error: '{source}' is not a valid directory or URL")
        sys.exit(1)
    return abs_path, False


# ---------------------------------------------------------------------------
# Scanner runners
# ---------------------------------------------------------------------------

def run_sast_scan(target_path) -> list:
    print("\n" + "=" * 60)
    print("  SAST (Static Application Security Testing)")
    print("=" * 60)
    framework_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sast_framework")
    subprocess.run(
        [sys.executable, os.path.join(framework_dir, "main.py"), target_path],
        cwd=framework_dir, check=False,
    )
    norm_path = os.path.join(framework_dir, "output", "normalized", "normalized_results.json")
    if os.path.exists(norm_path):
        with open(norm_path) as fh:
            findings = json.load(fh)
        for f in findings:
            f.setdefault("tool", f.get("scanner", "bandit"))
        return findings
    return []


def run_dast_scan(target_path) -> list:
    print("\n" + "=" * 60)
    print("  DAST (Dynamic Application Security Testing)")
    print("=" * 60)
    if not shutil.which("docker"):
        print("[!] Docker not found. Skipping DAST.")
        return []
    if not os.path.exists(os.path.join(target_path, "Dockerfile")):
        print(f"[!] No Dockerfile in {target_path}. Skipping DAST.")
        return []
    framework_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dast_framework")
    subprocess.run(
        [sys.executable, os.path.join(framework_dir, "main.py"), target_path],
        cwd=framework_dir, check=False,
    )
    findings = []
    output_dir = os.path.join(framework_dir, "output")
    for fname, tool in [("zap.json", "owasp-zap"), ("nuclei.jsonl", "nuclei"), ("ffuf.json", "ffuf")]:
        fpath = os.path.join(output_dir, fname)
        if not os.path.exists(fpath):
            continue
        try:
            if fname.endswith(".jsonl"):
                with open(fpath) as fh:
                    for line in fh:
                        if line.strip():
                            e = json.loads(line)
                            e["tool"] = tool
                            findings.append(e)
            else:
                with open(fpath) as fh:
                    data = json.load(fh)
                if tool == "owasp-zap":
                    sites = data.get("site", data.get("sites", []))
                    if isinstance(sites, dict):
                        sites = [sites]
                    for site in sites:
                        for alert in site.get("alerts", site.get("alertItems", [])):
                            instances = alert.get("instances", [])
                            url = (instances[0].get("uri", "") if instances
                                   else alert.get("url", ""))
                            findings.append({
                                "tool":          tool,
                                "vulnerability": alert.get("alert", alert.get("name", "Unknown")),
                                "severity":      alert.get("riskdesc", alert.get("risk", "unknown")),
                                "endpoint":      url,
                                "url":           url,
                                "cweid":         alert.get("cweid", ""),
                                "confidence":    alert.get("confidence", ""),
                                "desc":          alert.get("desc", alert.get("description", "")),
                                "param":         (instances[0].get("param", "") if instances
                                                  else alert.get("param", "")),
                            })
                elif tool == "ffuf" and "results" in data:
                    for r in data["results"]:
                        r["tool"] = tool
                        r["endpoint"] = r.get("url", "")
                        findings.append(r)
                elif isinstance(data, list):
                    for e in data:
                        e["tool"] = tool
                    findings.extend(data)
        except Exception as e:
            print(f"[!] Could not parse {fpath}: {e}")
    return findings


# ---------------------------------------------------------------------------
# Aggregator runner
# ---------------------------------------------------------------------------

def run_aggregator(output_dir):
    print("\n" + "=" * 60)
    print("  FINDINGS AGGREGATOR")
    print("=" * 60)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, base_dir)
    from aggregator import load_sast_findings, load_dast_findings, aggregate_findings

    sast_findings = load_sast_findings(base_dir)
    dast_findings = load_dast_findings(base_dir)

    print(f"[*] Loaded {len(sast_findings)} SAST findings")
    print(f"[*] Loaded {len(dast_findings)} DAST findings")

    result = aggregate_findings(sast_findings, dast_findings)
    summary = result["summary"]

    print(f"\n[+] Correlated (SAST+DAST match) : {summary['correlated']}")
    print(f"[+] Unmatched SAST               : {summary['sast_only']}")
    print(f"[+] Unmatched DAST               : {summary['dast_only']}")
    print(f"[+] Total findings               : {summary['total']}")

    if summary["correlated"]:
        print(f"\n[!] CORRELATED ({summary['correlated']}):")
        for f in result["findings"]:
            if f["match_type"] == "sast_dast_correlated":
                print(f"    [CWE-{f['cwe']}] [{f['severity']}] {f['vulnerability']}")
                print(f"          File    : {f['file']}")
                print(f"          Endpoint: {f['endpoint']}")

    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, "aggregated_report.json")
    with open(report_path, "w") as fh:
        json.dump(result, fh, indent=2)
    print(f"\n[+] Report saved to: {report_path}")
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="CVE Scanner Framework")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--sast", action="store_true", help="Run SAST only")
    mode.add_argument("--dast", action="store_true", help="Run DAST only")
    mode.add_argument("--all",  action="store_true", help="Run SAST + DAST + aggregator")

    parser.add_argument("target", nargs="?", default=".", help="Target path or URL")
    parser.add_argument("--output", default="output", help="Output directory")
    args = parser.parse_args()

    print("=" * 60)
    print("  CVE Scanner Framework")
    print(f"  Target: {args.target}")
    mode_str = "SAST" if args.sast else "DAST" if args.dast else "ALL"
    print(f"  Mode: {mode_str}")
    print(f"  Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    target_path, cloned = acquire_source(args.target)

    try:
        if args.sast or args.all:
            run_sast_scan(target_path)
        if args.dast or args.all:
            run_dast_scan(target_path)
    finally:
        if cloned and os.path.exists(target_path):
            shutil.rmtree(target_path, ignore_errors=True)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.output)

    if args.all:
        run_aggregator(out)

    print("\n" + "=" * 60 + "\n  SCAN COMPLETE\n" + "=" * 60)


if __name__ == "__main__":
    main()