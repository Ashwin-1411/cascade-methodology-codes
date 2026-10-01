"""
dast_framework/scanners/zap_scanner.py  — FINAL WORKING VERSION
================================================================
Root cause of all previous failures identified and fixed.

The problem: ZAP's accessUrl API does NOT send cookies.
  - accessUrl hit /vulnerabilities/sqli/?id=1&Submit=Submit
  - DVWA returned 302 → login.php (no session cookie in request)
  - ZAP recorded login.php in scan tree, not the vuln page
  - Active scan found nothing to attack

The fix: seed URLs by making real requests THROUGH ZAP's proxy
  (port 8081) with the session cookie. When traffic passes through
  ZAP's proxy, it records the URL in the scan tree WITH the full
  response. Then active scan has real pages to attack.

Confirmed working: debug3.py scan found 4 High SQLi findings in 170s
  - SQL Injection - MySQL
  - Advanced SQL Injection - boolean-based blind
  - Advanced SQL Injection - error-based  
  - Advanced SQL Injection - time-based blind (SLEEP)
  - Advanced SQL Injection - UNION query
"""

import json
import os
import re
import time

import requests
import urllib3
urllib3.disable_warnings()

from urllib.parse import urlparse
from .base import Scanner
from ..core.docker_runner import APP_PORT

ZAP_HOST_PORT = 8081
ZAP_API_KEY   = "65a06u0hrv0l02utnag55lgeh7"
ZAP_API       = f"http://127.0.0.1:{ZAP_HOST_PORT}"
POLICY_NAME   = "dvwa-injection-policy"

SPIDER_TIMEOUT_S = 300
ASCAN_TIMEOUT_S  = 7200   # 2 hours for all URLs
POLL_INTERVAL_S  = 15

DVWA_SEED_PATHS = [
    "/",
    "/index.php",
    "/vulnerabilities/sqli/?id=1&Submit=Submit",
    "/vulnerabilities/sqli_blind/?id=1&Submit=Submit",
    "/vulnerabilities/xss_r/?name=test",
    "/vulnerabilities/xss_s/",
    "/vulnerabilities/xss_d/?default=English",
    "/vulnerabilities/exec/?ip=127.0.0.1&Submit=Submit",
    "/vulnerabilities/fi/?page=file1.php",
    "/vulnerabilities/upload/",
    "/vulnerabilities/open_redirect/?redirect=info",
    "/vulnerabilities/brute/?username=admin&password=test&Login=Login",
    "/vulnerabilities/csrf/",
    "/phpinfo.php",
]

INJECTION_KEYWORDS = [
    "sql", "xss", "cross site script", "command", "injection",
    "traversal", "inclusion", "remote file", "local file",
    "ssti", "xxe", "ssrf", "code inject", "remote os",
    "shell", "ldap", "xpath", "template",
]


class ZapScanner(Scanner):
    name: str = "owasp-zap"
    output_filename: str = "zap.json"

    def run(self, target_url: str, output_dir: str = ".") -> None:
        abs_output_dir = os.path.abspath(output_dir)
        os.makedirs(abs_output_dir, exist_ok=True)
        host_target = f"http://localhost:{APP_PORT}"

        print(f"    [*] ZAP on port {ZAP_HOST_PORT} | Target: {host_target}")

        if not self._zap_is_alive():
            print(f"    [!] ZAP not reachable on port {ZAP_HOST_PORT}")
            return

        rule_count = self._get_rule_count()
        print(f"    [+] ZAP alive — {rule_count} scan rules loaded")
        if rule_count < 100:
            print(f"    [!] Only {rule_count} rules — install 'Active Scan Rules' addon")

        # Phase 1: Login to DVWA directly and get session cookie
        session_cookie = self._login_dvwa(host_target)
        if not session_cookie:
            print("    [!] Login failed — cannot scan authenticated pages")
            return
        print(f"    [+] DVWA session: PHPSESSID={session_cookie[:8]}...")

        # Phase 2: Set security=low
        self._set_security_low(host_target, session_cookie)

        # Phase 3: Seed URLs into ZAP scan tree via proxy
        # This is the KEY FIX — must go through ZAP proxy, not accessUrl API
        print("    [*] Seeding vulnerability URLs through ZAP proxy...")
        seeded = self._seed_urls_via_proxy(host_target, session_cookie)
        print(f"    [+] Seeded {seeded}/{len(DVWA_SEED_PATHS)} URLs into ZAP scan tree")

        # Phase 4: Inject session into ZAP session manager
        self._inject_session_into_zap(host_target, session_cookie)

        # Phase 5: Build injection policy
        print("    [*] Building injection scan policy...")
        enabled = self._build_injection_policy()
        print(f"    [+] Policy '{POLICY_NAME}': {enabled} injection rules at HIGH strength")

        # Phase 6: Spider (now scan tree is populated)
        print("    [*] Running ZAP spider...")
        self._run_spider(host_target)

        # Phase 7: Active scan each vuln URL — recurse=false, GET+POST
        print(f"    [*] Running active scan with '{POLICY_NAME}'...")
        print(f"    [*] ~170s per URL × {len(DVWA_SEED_PATHS)} URLs = expect 30-60 min...")
        self._run_active_scan(host_target)

        # Phase 8: Export
        report_path = os.path.join(abs_output_dir, self.output_filename)
        self._export_report(report_path)

        if os.path.exists(report_path):
            with open(report_path) as f:
                data = json.load(f)
            sites = data.get("site", [])
            if isinstance(sites, dict):
                sites = [sites]
            all_alerts = [a for s in sites for a in s.get("alerts", [])]
            high       = [a for a in all_alerts if any(
                x in a.get("riskdesc","").lower() for x in ["high","critical"])]
            injection  = [a for a in all_alerts if any(
                x in a.get("alert","").lower() for x in [
                    "sql","xss","injection","traversal","command","inclusion"])]
            print(f"    [+] ZAP complete — {len(all_alerts)} alert types, "
                  f"{len(high)} High/Critical, {len(injection)} injection findings")
        else:
            print("    [!] Report not generated")

    # ------------------------------------------------------------------
    # Authentication — direct requests, NOT through ZAP proxy
    # ------------------------------------------------------------------

    def _login_dvwa(self, host_base: str) -> str:
        """
        Login to DVWA using requests.Session() directly (not via proxy).
        Returns PHPSESSID cookie value.

        Handles both:
          - DISABLE_AUTHENTICATION=true: any GET gives session immediately
          - Standard login: POST username/password with CSRF token
        """
        s = requests.Session()

        # Try auth-bypass first (cve_fixed/DVWA image)
        try:
            r = s.get(host_base.rstrip("/") + "/index.php",
                      allow_redirects=True, timeout=10)
            phpsessid = s.cookies.get("PHPSESSID", "")
            if phpsessid and "login" not in r.url:
                print("    [+] Session via auth-bypass mode")
                return phpsessid
        except Exception:
            pass

        # Standard login — use curl via subprocess to handle duplicate Set-Cookie headers
        # that the requests library raises an exception on (DVWA sets PHPSESSID 4 times).
        try:
            import subprocess, tempfile
            login_url = host_base.rstrip("/") + "/login.php"
            cookiefile = tempfile.mktemp(suffix=".txt")

            # GET to seed session + grab CSRF token
            get_result = subprocess.run(
                ["curl", "-s", "-L", "-c", cookiefile, login_url],
                capture_output=True, text=True, timeout=15,
            )
            token = ""
            m = re.search(r"user_token[^>]+value=['\"]([a-f0-9]+)['\"]", get_result.stdout)
            if not m:
                m = re.search(r"value=['\"]([a-f0-9]{32})['\"]", get_result.stdout)
            if m:
                token = m.group(1)

            # POST login with CSRF token, follow redirect
            post_result = subprocess.run(
                ["curl", "-s", "-L", "-c", cookiefile, "-b", cookiefile,
                 "-X", "POST", login_url,
                 "-d", f"username=admin&password=password&Login=Login&user_token={token}",
                 "-w", "%{url_effective}"],
                capture_output=True, text=True, timeout=15,
            )
            final_url = post_result.stdout.rsplit("\n", 1)[-1].strip()

            # Extract PHPSESSID from cookie jar file (last occurrence wins)
            phpsessid = ""
            try:
                with open(cookiefile) as cf:
                    for line in cf:
                        parts = line.strip().split("\t")
                        if len(parts) >= 7 and parts[5] == "PHPSESSID":
                            phpsessid = parts[6]
            except Exception:
                pass

            if phpsessid and "login" not in final_url:
                print("    [+] Session via login form (curl)")
                s.cookies.set("PHPSESSID", phpsessid)
                s.cookies.set("security", "low")
                return phpsessid
            else:
                print(f"    [!] Login landed at: {final_url}")
        except Exception as e:
            print(f"    [!] Login failed: {e}")

        return ""

    def _set_security_low(self, host_base: str, phpsessid: str):
        """Set DVWA security level to LOW via security.php POST."""
        try:
            s = requests.Session()
            s.cookies.set("PHPSESSID", phpsessid)
            r = s.get(host_base.rstrip("/") + "/security.php", timeout=10)
            token = ""
            m = re.search(r"value=['\"]([a-f0-9]{32})['\"]", r.text)
            if m:
                token = m.group(1)
            s.post(host_base.rstrip("/") + "/security.php",
                   data={"security": "low", "seclev_submit": "Submit",
                         "user_token": token},
                   allow_redirects=True, timeout=10)
            print("    [+] DVWA security level set to LOW")
        except Exception as e:
            print(f"    [!] Failed to set security level: {e}")

    # ------------------------------------------------------------------
    # URL seeding — THE KEY FIX: go through ZAP proxy, not accessUrl API
    # ------------------------------------------------------------------

    def _seed_urls_via_proxy(self, host_base: str, phpsessid: str) -> int:
        """
        Make real HTTP requests through ZAP's proxy (port 8081) with the
        session cookie. This is the only reliable way to get URLs into
        ZAP's scan tree so active scan can find them.

        accessUrl API does NOT send cookies → 302 to login.php → wrong URL
        recorded in scan tree → active scan finds nothing to attack.

        Proxy requests send cookies → 200 OK → correct page recorded →
        active scan has real injection points to test.
        """
        proxies = {
            "http":  f"http://127.0.0.1:{ZAP_HOST_PORT}",
            "https": f"http://127.0.0.1:{ZAP_HOST_PORT}",
        }
        cookies = {"PHPSESSID": phpsessid, "security": "low"}
        seeded  = 0

        for path in DVWA_SEED_PATHS:
            url = host_base.rstrip("/") + path
            try:
                r = requests.get(url, proxies=proxies, cookies=cookies,
                                 timeout=15, verify=False, allow_redirects=True)
                if r.status_code == 200 and "login" not in r.url:
                    seeded += 1
                else:
                    print(f"    [!] {path} → {r.status_code} / {r.url}")
            except Exception as e:
                print(f"    [!] Proxy seed failed for {path}: {e}")

        time.sleep(2)
        return seeded

    def _inject_session_into_zap(self, zap_target: str, phpsessid: str):
        """Register PHPSESSID with ZAP's httpsessions manager."""
        site = zap_target
        self._zap_get("httpsessions/action/addSessionToken",
                      {"site": site, "sessionToken": "PHPSESSID"})
        self._zap_get("httpsessions/action/createEmptySession",
                      {"site": site, "session": "dvwa-session"})
        self._zap_get("httpsessions/action/setSessionTokenValue",
                      {"site": site, "session": "dvwa-session",
                       "sessionToken": "PHPSESSID", "tokenValue": phpsessid})
        self._zap_get("httpsessions/action/setActiveSession",
                      {"site": site, "session": "dvwa-session"})
        print(f"    [+] ZAP session manager updated")

    # ------------------------------------------------------------------
    # Scan policy — no disableAllScanners (keeps Injection category active)
    # ------------------------------------------------------------------

    def _build_injection_policy(self) -> int:
        self._zap_get("ascan/action/removeScanPolicy",
                      {"scanPolicyName": POLICY_NAME})
        self._zap_get("ascan/action/addScanPolicy",
                      {"scanPolicyName": POLICY_NAME,
                       "attackStrength": "HIGH",
                       "alertThreshold": "LOW"})

        r            = self._zap_get("ascan/view/scanners")
        all_scanners = r.get("scanners", [])
        enabled      = 0

        for scanner in all_scanners:
            name = scanner.get("name", "").lower()
            sid  = str(scanner.get("id", ""))
            if any(kw in name for kw in INJECTION_KEYWORDS):
                r1 = self._zap_get("ascan/action/enableScanners",
                                   {"ids": sid, "scanPolicyName": POLICY_NAME})
                self._zap_get("ascan/action/setScannerAttackStrength",
                              {"id": sid, "attackStrength": "HIGH",
                               "scanPolicyName": POLICY_NAME})
                self._zap_get("ascan/action/setScannerAlertThreshold",
                              {"id": sid, "alertThreshold": "LOW",
                               "scanPolicyName": POLICY_NAME})
                if r1.get("Result") == "OK":
                    enabled += 1
                    print(f"    [+] Enabled: [{sid}] {scanner.get('name','')}")
        return enabled

    # ------------------------------------------------------------------
    # Spider
    # ------------------------------------------------------------------

    def _run_spider(self, target: str):
        r       = self._zap_get("spider/action/scan",
                                {"url": target, "recurse": "true",
                                 "maxChildren": "100"})
        scan_id = r.get("scan", "0") if r else "0"
        self._wait_for_single("spider/view/status", scan_id,
                              SPIDER_TIMEOUT_S, "Spider")

    # ------------------------------------------------------------------
    # Active scan
    # ------------------------------------------------------------------

    def _run_active_scan(self, target: str):
        """
        Queue one GET scan per DVWA vulnerability URL with recurse=false.
        Also queue POST scans for form-heavy pages.

        recurse=false: scan EXACTLY the URL given including query params.
        Without this ZAP follows /vulnerabilities/sqli → redirect → strips params.
        """
        scan_ids = []
        base     = target.rstrip("/")

        for path in DVWA_SEED_PATHS:
            url = base + path

            # GET scan
            r = self._zap_get("ascan/action/scan",
                              {"url": url, "recurse": "false",
                               "scanPolicyName": POLICY_NAME,
                               "method": "GET", "postData": ""})
            if r and "scan" in r:
                sid = int(r["scan"])
                scan_ids.append(sid)
                print(f"    [*] Queued GET #{sid}: {path}")
            else:
                print(f"    [!] Failed to queue {path}: {r}")

            # POST scan for form pages
            if any(x in path for x in ["xss_s", "upload", "exec",
                                        "sqli", "brute", "fi", "csrf"]):
                r = self._zap_get("ascan/action/scan",
                                  {"url": url, "recurse": "false",
                                   "scanPolicyName": POLICY_NAME,
                                   "method": "POST", "postData": ""})
                if r and "scan" in r:
                    sid = int(r["scan"])
                    scan_ids.append(sid)
                    print(f"    [*] Queued POST #{sid}: {path}")

        if not scan_ids:
            print("    [!] No scans queued — check scan tree population")
            return

        print(f"    [*] Waiting for {len(scan_ids)} scans...")
        self._wait_for_all_scans(scan_ids)

    def _wait_for_all_scans(self, scan_ids: list):
        """
        Wait until every scan in scan_ids reaches 100%.

        Filter strictly to OUR scan IDs (integers) to avoid counting
        old completed scans from previous runs which caused instant exit.
        """
        start       = time.time()
        scan_id_set = set(int(s) for s in scan_ids)
        last_log    = ""

        while time.time() - start < ASCAN_TIMEOUT_S:
            all_scans = self._zap_get("ascan/view/scans").get("scans", [])

            # ONLY look at our current scan IDs
            our_scans = [s for s in all_scans
                         if int(s.get("id", -1)) in scan_id_set]

            if not our_scans:
                time.sleep(POLL_INTERVAL_S)
                continue

            done    = [s for s in our_scans
                       if int(s.get("progress", 0)) >= 100]
            running = [s for s in our_scans
                       if int(s.get("progress", 0)) < 100]
            elapsed = int(time.time() - start)

            if running:
                slowest     = min(running,
                                  key=lambda s: int(s.get("progress", 0)))
                pct         = slowest.get("progress", 0)
                sid         = slowest.get("id", "?")
                total_reqs  = sum(int(s.get("reqCount", 0)) for s in our_scans)
                log = (f"{len(done)}/{len(scan_ids)} done, "
                       f"slowest=#{sid} at {pct}% "
                       f"({total_reqs} reqs, {elapsed}s)")
                if log != last_log:
                    print(f"    [*] {log}")
                    last_log = log
            else:
                total_reqs = sum(int(s.get("reqCount", 0)) for s in our_scans)
                print(f"    [+] All {len(scan_ids)} scans complete! "
                      f"({total_reqs} total requests, {elapsed}s)")
                return

            time.sleep(POLL_INTERVAL_S)

        print(f"    [!] Timeout ({ASCAN_TIMEOUT_S}s) — using results so far")

    def _wait_for_single(self, endpoint: str, scan_id: str,
                         timeout: int, label: str):
        start    = time.time()
        last_pct = -1
        while time.time() - start < timeout:
            r = self._zap_get(endpoint, {"scanId": scan_id})
            try:
                pct = int(r.get("status", "0"))
            except (ValueError, TypeError):
                pct = 0
            if pct != last_pct:
                elapsed = int(time.time() - start)
                print(f"    [*] {label}: {pct}% ({elapsed}s)")
                last_pct = pct
            if pct >= 100:
                print(f"    [+] {label} complete.")
                return
            time.sleep(POLL_INTERVAL_S)
        print(f"    [!] {label} timed out")

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def _export_report(self, output_path: str):
        try:
            r = requests.get(f"{ZAP_API}/OTHER/core/other/jsonreport/",
                             params={"apikey": ZAP_API_KEY}, timeout=60)
            if r.status_code == 200 and r.content:
                with open(output_path, "wb") as f:
                    f.write(r.content)
                print(f"    [+] Report exported to {output_path}")
                return
        except Exception as e:
            print(f"    [!] Report endpoint failed: {e}")
        try:
            r       = requests.get(f"{ZAP_API}/JSON/core/view/alerts/",
                                   params={"apikey": ZAP_API_KEY,
                                           "start": "0", "count": "10000"},
                                   timeout=30)
            alerts  = r.json().get("alerts", [])
            report  = {"site": [{"alerts": alerts}]}
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)
            print(f"    [+] Report written ({len(alerts)} alerts)")
        except Exception as e:
            print(f"    [!] Fallback failed: {e}")

    # ------------------------------------------------------------------
    # ZAP helpers
    # ------------------------------------------------------------------

    def _zap_is_alive(self) -> bool:
        try:
            return bool(self._zap_get("core/view/version").get("version"))
        except Exception:
            return False

    def _get_rule_count(self) -> int:
        return len(self._zap_get("ascan/view/scanners").get("scanners", []))

    def _zap_get(self, endpoint: str, params: dict = None) -> dict:
        try:
            p = {"apikey": ZAP_API_KEY}
            if params:
                p.update(params)
            r = requests.get(f"{ZAP_API}/JSON/{endpoint}/",
                             params=p, timeout=30)
            return r.json()
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Result parsing
    # ------------------------------------------------------------------

    def _normalize_severity(self, severity_raw: str) -> str:
        if not severity_raw:
            return "unknown"
        return severity_raw.split()[0].lower()

    def _normalize_endpoint(self, url: str) -> str:
        try:
            return urlparse(url).path
        except Exception:
            return url

    def _cwe_fallback(self, alert_name: str) -> str:
        mapping = {
            "sql injection":        "89",
            "cross site scripting": "79",
            "xss":                  "79",
            "command injection":    "78",
            "path traversal":       "22",
            "open redirect":        "601",
            "file inclusion":       "22",
            "xxe":                  "611",
            "ssrf":                 "918",
            "idor":                 "639",
        }
        name_lower = alert_name.lower()
        for key, cwe in mapping.items():
            if key in name_lower:
                return cwe
        return ""

    def parse_results(self, output_dir=".") -> list:
        findings     = []
        output_file  = os.path.join(output_dir, self.output_filename)
        if not os.path.exists(output_file):
            return findings
        try:
            with open(output_file) as f:
                data = json.load(f)
            sites = data.get("site", data.get("sites", []))
            if isinstance(sites, dict):
                sites = [sites]
            for site in sites:
                for alert in site.get("alerts", site.get("alertItems", [])):
                    instances    = alert.get("instances", [])
                    url          = (instances[0].get("uri", "") if instances
                                    else alert.get("url", alert.get("uri", "")))
                    param        = ""
                    if instances:
                        param    = (instances[0].get("param", "")
                                    or instances[0].get("attack", ""))
                    severity_raw = alert.get("riskdesc", alert.get("risk", ""))
                    severity     = self._normalize_severity(severity_raw)
                    cweid        = alert.get("cweid", "")
                    if not cweid or cweid == "0":
                        cweid    = self._cwe_fallback(alert.get("alert", ""))
                    findings.append({
                        "tool":          self.name,
                        "vulnerability": alert.get("alert",
                                                   alert.get("name", "Unknown")),
                        "severity":      severity,
                        "severity_raw":  severity_raw,
                        "endpoint":      self._normalize_endpoint(url),
                        "url":           url,
                        "confidence":    alert.get("confidence", ""),
                        "cweid":         cweid,
                        "desc":          alert.get("desc",
                                                   alert.get("description", "")),
                        "param":         param,
                    })
        except Exception as e:
            print(f"[!] Error parsing ZAP results: {e}")
        return findings
        