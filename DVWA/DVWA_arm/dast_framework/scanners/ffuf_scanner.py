"""
ffuf endpoint discovery — no-auth mode.
DVWA authentication is disabled at container level via env var.
Simple, fast, no cookie management needed.
"""

import subprocess
import json
import os
import shutil
from .base import Scanner


class FfufScanner(Scanner):
    name: str = "ffuf"
    output_filename: str = "ffuf.json"

    def run(self, target_url: str, output_dir: str = ".") -> None:
        output_file = os.path.join(output_dir, self.output_filename)
        framework_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        wordlist = os.path.join(framework_dir, "wordlists", "common.txt")

        if not os.path.exists(wordlist):
            print(f"[!] Wordlist not found: {wordlist}")
            return

        if not shutil.which("ffuf"):
            print("[!] ffuf not found in PATH. Skipping endpoint discovery.")
            return

        all_results = []
        tmp_root = output_file + ".root.json"

        # Pass 1: root path fuzzing
        subprocess.run([
            "ffuf", "-u", f"{target_url}/FUZZ",
            "-w", wordlist,
            "-o", tmp_root, "-of", "json",
            "-mc", "200,301,302,403,500",
            "-t", "50", "-timeout", "10",
        ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if os.path.exists(tmp_root):
            try:
                with open(tmp_root) as f:
                    all_results.extend(json.load(f).get("results", []))
            except Exception:
                pass

        # Pass 2: DVWA vulnerability paths
        dvwa_wordlist = os.path.join(framework_dir, "wordlists", "dvwa_paths.txt")
        if not os.path.exists(dvwa_wordlist):
            os.makedirs(os.path.dirname(dvwa_wordlist), exist_ok=True)
            with open(dvwa_wordlist, "w") as f:
                f.write("\n".join([
                    "sqli", "sqli_blind", "xss_r", "xss_s", "xss_d",
                    "exec", "fi", "upload", "csrf", "captcha",
                    "javascript", "open_redirect", "weak_id", "authbypass", "brute", "api",
                ]))

        tmp_vuln = output_file + ".vuln.json"
        subprocess.run([
            "ffuf", "-u", f"{target_url}/vulnerabilities/FUZZ/",
            "-w", dvwa_wordlist,
            "-o", tmp_vuln, "-of", "json",
            "-mc", "200,302,403",
            "-t", "20", "-timeout", "10",
        ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if os.path.exists(tmp_vuln):
            try:
                with open(tmp_vuln) as f:
                    all_results.extend(json.load(f).get("results", []))
            except Exception:
                pass

        with open(output_file, "w") as f:
            json.dump({"results": all_results}, f, indent=2)

    def parse_results(self, output_dir="."):
        findings = []
        output_file = os.path.join(output_dir, self.output_filename)
        if not os.path.exists(output_file):
            return findings
        try:
            with open(output_file) as f:
                data = json.load(f)
            for result in data.get("results", []):
                findings.append({
                    "tool":       self.name,
                    "type":       "endpoint",
                    "endpoint":   result.get("url", ""),
                    "status":     result.get("status"),
                    "confidence": "high",
                })
        except Exception as e:
            print(f"[!] Error parsing ffuf results: {e}")
        return findings