"""
Central controller for running all DAST scanners.
"""

import os
from dast_framework.scanners.ffuf_scanner import FfufScanner
from dast_framework.scanners.zap_scanner import ZapScanner
from dast_framework.scanners.nuclei_scanner import NucleiScanner

ffuf_scanner = FfufScanner()
zap_scanner = ZapScanner()
nuclei_scanner = NucleiScanner()


def run_dast(runtime):
    """
    Run all DAST scanners against the target.

    Args:
        runtime: Dict with 'host_url', 'container_url', 'container_id'

    Returns:
        List of findings from all scanners
    """
    findings = []

    host_url = runtime["host_url"]
    container_url = runtime["container_url"]

    # Determine output directory
    framework_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_dir = os.path.join(framework_dir, "output")
    os.makedirs(output_dir, exist_ok=True)

    # Host-based tool: ffuf for endpoint discovery
    try:
        print("[*] Running ffuf (endpoint discovery)...")
        ffuf_scanner.run(host_url, output_dir)
        ffuf_findings = ffuf_scanner.parse_results(output_dir)
        findings.extend(ffuf_findings)
        print(f"    Found {len(ffuf_findings)} endpoints")
    except Exception as e:
        print(f"[!] ffuf scanner error: {e}")

    # Container-based tool: OWASP ZAP
    try:
        print("[*] Running OWASP ZAP (vulnerability scanner)...")
        zap_scanner.run(container_url, output_dir)
        zap_findings = zap_scanner.parse_results(output_dir)
        findings.extend(zap_findings)
        print(f"    Found {len(zap_findings)} vulnerabilities")
    except Exception as e:
        print(f"[!] ZAP scanner error: {e}")

    # Container-based tool: Nuclei
    try:
        print("[*] Running Nuclei (CVE & misconfiguration scanner)...")
        nuclei_scanner.run(container_url, output_dir)
        nuclei_findings = nuclei_scanner.parse_results(output_dir)
        findings.extend(nuclei_findings)
        print(f"    Found {len(nuclei_findings)} vulnerabilities")
    except Exception as e:
        print(f"[!] Nuclei scanner error: {e}")

    return findings
