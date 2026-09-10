#!/usr/bin/env python3
"""
patch_tester.py – Functional regression harness for LLM-generated DVWA patches.

For every patched file in dvwa_v3_l0_outputs/, dvwa_v3_l1_outputs/, and
dvwa_v3_l2_outputs/:
  1. Start DVWA in Docker, wait for readiness, initialise DB, log in.
  2. BASELINE  – request each module/level unmodified; record status/length/errors.
  3. PATCHED   – swap in the patch file (docker cp), re-request, restore original.
  4. Emit baseline.json, patched.json, results.csv, and a summary.

Module probe strategy (documented below in MODULE_PROBES):
  Most modules render by GET with no required parameters; a handful need a POST
  or a specific query string to avoid a redirect or to exercise the include().
  The probe is designed to trigger normal page rendering, not to exploit anything.

Run:
  python patch_tester.py [--skip-docker]   (--skip-docker if DVWA is already up)
"""

import argparse
import csv
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from copy import deepcopy
from datetime import datetime
from pathlib import Path

import requests

# ── paths ─────────────────────────────────────────────────────────────────────
PROJECT_DIR  = Path(__file__).parent
COMPOSE_DIR  = PROJECT_DIR / "DVWA"
LOG_FILE     = PROJECT_DIR / "patch_tester.log"
BASELINE_JSON = PROJECT_DIR / "baseline.json"
PATCHED_JSON  = PROJECT_DIR / "patched.json"
RESULTS_CSV   = PROJECT_DIR / "results.csv"

OUTPUT_DIRS = {
    "l0": PROJECT_DIR / "dvwa_v3_l0_outputs" / "dvwa_v3_l0_outputs",
    "l1": PROJECT_DIR / "dvwa_v3_l1_outputs" / "dvwa_v3_l1_outputs",
    "l2": PROJECT_DIR / "dvwa_v3_l2_outputs" / "dvwa_v3_l2_outputs",
}

BASE_URL             = "http://127.0.0.1:4280"
CONTAINER_VULN_BASE  = "/var/www/html/vulnerabilities"

# Auto-detected at startup
CONTAINER = "dvwa-dvwa-1"

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("patch_tester")

# ── PHP error patterns ─────────────────────────────────────────────────────────
# Must look like actual PHP error output, not JavaScript identifiers.
# PHP emits errors as:  <b>Fatal error</b>:  or  PHP Fatal error:  or
# the uncaught-exception form.  We require the PHP-specific prefix/context.
PHP_ERROR_RE = re.compile(
    r"(<b>(?:Fatal error|Parse error|Warning|Notice|Deprecated)</b>\s*:)"
    r"|(?:PHP (?:Fatal error|Parse error|Warning|Notice|Deprecated)\s*:)"
    r"|(?:Uncaught (?:Error|Exception|TypeError|ValueError)\b)"
    r"|(?:Call to undefined (?:function|method)\b)"
    r"|(?:syntax error,? unexpected\b)",
    re.IGNORECASE,
)

# ── module probes ──────────────────────────────────────────────────────────────
# Each entry: url_path, method ("GET"|"POST"), params/data dict.
# The probe exercises normal page rendering without exploiting.
#
# Rationale for non-trivial cases:
#   exec        – POST with a valid IP; otherwise the form is blank (status 200 either way,
#                 but the source file is only executed when the form is submitted).
#   sqli        – GET with id=1&Submit=Submit triggers the DB query in source/<level>.php.
#   sqli_blind  – same; source file runs only when id is supplied.
#   fi          – GET with page=include.php (the safe default); source file sets $file then
#                 the index does include($file).  Without ?page= some levels 404 or show
#                 a blank page because $file is unset.
#   xss_d       – GET with default=English (the factory default); avoids a JS redirect.
#   open_redirect – GET with redirect=/ (a local path); source file is executed and issues
#                 header("Location: /") which curl follows harmlessly.  allow_redirects=True
#                 so the 302 itself doesn't appear as a failure.
#   weak_id     – GET with Generate=Generate to trigger the session-ID generation logic.
#   brute       – GET with username=admin&password=password&Login=Login; source file runs
#                 the authentication query.
#   captcha     – two-step: POST step1 params so the PHP logic in source/<level>.php is
#                 exercised (it does form validation, not real CAPTCHA on level low/medium).
#   csrf        – GET; the form is returned; we don't need to submit it.
#   upload      – GET; just loads the upload form.
#   api         – GET with id=1; the API source files perform a DB look-up.
#   authbypass  – GET; source file just sets $role from session/cookie.
#   bac         – GET; just loads the page.
#   csp         – POST with include=https://pastebin.com to trigger the nonce logic.
#   javascript  – GET with token=XXX&phrase=success (to hit the validation branch).
#   xss_r       – GET with name=probe (benign; source file echoes it).
#   xss_s       – POST a benign guestbook entry; source file runs the INSERT.

MODULE_PROBES = {
    "sqli": {
        "url":    "/vulnerabilities/sqli/",
        "method": "GET",
        "params": {"id": "1", "Submit": "Submit"},
    },
    "sqli_blind": {
        "url":    "/vulnerabilities/sqli_blind/",
        "method": "GET",
        "params": {"id": "1", "Submit": "Submit"},
    },
    "exec": {
        "url":    "/vulnerabilities/exec/",
        "method": "POST",
        "data":   {"ip": "127.0.0.1", "Submit": "Submit"},
    },
    "xss_r": {
        "url":    "/vulnerabilities/xss_r/",
        "method": "GET",
        "params": {"name": "probe"},
    },
    "xss_s": {
        "url":    "/vulnerabilities/xss_s/",
        "method": "POST",
        "data":   {"txtName": "probe", "mtxMessage": "probe message",
                   "btnSign": "Sign+Guestbook"},
    },
    "xss_d": {
        "url":    "/vulnerabilities/xss_d/",
        "method": "GET",
        "params": {"default": "English"},
    },
    "fi": {
        "url":    "/vulnerabilities/fi/",
        "method": "GET",
        "params": {"page": "include.php"},
    },
    "open_redirect": {
        "url":    "/vulnerabilities/open_redirect/",
        "method": "GET",
        "params": {"redirect": "/"},
        "allow_redirects": True,
    },
    "weak_id": {
        "url":    "/vulnerabilities/weak_id/",
        "method": "GET",
        "params": {"Generate": "Generate"},
    },
    "brute": {
        "url":    "/vulnerabilities/brute/",
        "method": "GET",
        "params": {"username": "admin", "password": "password", "Login": "Login"},
    },
    "captcha": {
        "url":    "/vulnerabilities/captcha/",
        "method": "POST",
        "data":   {
            "step":              "1",
            "password_new":      "Passw0rd!",
            "password_conf":     "Passw0rd!",
            "Change":            "Change",
        },
    },
    "csrf": {
        "url":    "/vulnerabilities/csrf/",
        "method": "GET",
        "params": {},
    },
    "upload": {
        "url":    "/vulnerabilities/upload/",
        "method": "GET",
        "params": {},
    },
    "api": {
        "url":    "/vulnerabilities/api/",
        "method": "GET",
        "params": {"id": "1"},
    },
    "authbypass": {
        "url":    "/vulnerabilities/authbypass/",
        "method": "GET",
        "params": {},
    },
    "bac": {
        "url":    "/vulnerabilities/bac/",
        "method": "GET",
        "params": {},
    },
    "csp": {
        "url":    "/vulnerabilities/csp/",
        "method": "POST",
        "data":   {"include": "https://pastebin.com", "Include": "Include"},
    },
    "javascript": {
        "url":    "/vulnerabilities/javascript/",
        "method": "GET",
        "params": {"token": "XXX", "phrase": "success", "send": "Submit"},
    },
}

# ── docker helpers ─────────────────────────────────────────────────────────────

def docker_start():
    log.info("Starting DVWA docker containers …")
    r = subprocess.run(
        ["docker", "compose", "up", "-d"],
        cwd=str(COMPOSE_DIR), capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0:
        log.error("docker compose up failed:\n%s", r.stderr)
        sys.exit(1)
    log.info("Containers started (or already running).")


def detect_container() -> str:
    r = subprocess.run(
        ["docker", "compose", "ps", "-q", "dvwa"],
        cwd=str(COMPOSE_DIR), capture_output=True, text=True, timeout=15,
    )
    if r.returncode == 0 and r.stdout.strip():
        cid = r.stdout.strip().splitlines()[0]
        nr = subprocess.run(
            ["docker", "inspect", "--format", "{{.Name}}", cid],
            capture_output=True, text=True, timeout=10,
        )
        if nr.returncode == 0:
            return nr.stdout.strip().lstrip("/")
    return CONTAINER


def docker_cp_to_container(local: Path, remote_path: str):
    r = subprocess.run(
        ["docker", "cp", str(local), f"{CONTAINER}:{remote_path}"],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        raise RuntimeError(f"docker cp →container failed: {r.stderr.strip()}")


def docker_cp_from_container(remote_path: str, local: Path):
    r = subprocess.run(
        ["docker", "cp", f"{CONTAINER}:{remote_path}", str(local)],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        raise RuntimeError(f"docker cp ←container failed: {r.stderr.strip()}")


def wait_for_dvwa(timeout: int = 120):
    log.info("Waiting for DVWA at %s …", BASE_URL)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(BASE_URL + "/login.php", timeout=5)
            if r.status_code == 200:
                log.info("DVWA is up.")
                return
        except Exception:
            pass
        time.sleep(3)
    log.error("DVWA did not become ready in %ds.", timeout)
    sys.exit(1)


# ── DVWA session helpers ───────────────────────────────────────────────────────

def dvwa_setup(session: requests.Session):
    """Hit setup.php to (re-)create the database."""
    log.info("Running setup.php …")
    r = session.get(BASE_URL + "/setup.php", timeout=15)
    r = session.post(
        BASE_URL + "/setup.php",
        data={"create_db": "Create / Reset Database"},
        timeout=30,
    )
    if "Database Setup" in r.text or r.status_code == 200:
        log.info("DB setup OK (status %d).", r.status_code)
    else:
        log.warning("setup.php returned unexpected status %d.", r.status_code)
    time.sleep(2)


def dvwa_login(session: requests.Session) -> str:
    """Log in as admin/password; return PHPSESSID."""
    log.info("Logging in as admin …")
    r = session.get(BASE_URL + "/login.php", timeout=10)
    token = ""
    m = re.search(r'name=["\']user_token["\'][^>]*value=["\']([^"\']+)', r.text)
    if m:
        token = m.group(1)

    r = session.post(
        BASE_URL + "/login.php",
        data={
            "username":   "admin",
            "password":   "password",
            "Login":      "Login",
            "user_token": token,
        },
        allow_redirects=True,
        timeout=15,
    )
    if "logout" in r.text.lower() or r.url.endswith("index.php"):
        phpsessid = session.cookies.get("PHPSESSID", "")
        log.info("Logged in. PHPSESSID=%s", phpsessid)
        return phpsessid
    log.error("Login failed (status %d). Body snippet: %s", r.status_code, r.text[:300])
    sys.exit(1)


# ── request helper ─────────────────────────────────────────────────────────────

def probe_module(session: requests.Session, module: str, level: str) -> dict:
    """
    Send the probe request for module/level.
    Returns dict with keys: status, length, has_error, body_snippet.
    """
    probe = MODULE_PROBES.get(module)
    if probe is None:
        return {"status": -1, "length": 0, "has_error": False,
                "body_snippet": f"no probe config for {module}"}

    # Set security level via cookie
    session.cookies.set("security", level, domain="127.0.0.1")

    url     = BASE_URL + probe["url"]
    method  = probe.get("method", "GET").upper()
    allow_r = probe.get("allow_redirects", True)

    try:
        if method == "GET":
            resp = session.get(url, params=probe.get("params", {}),
                               allow_redirects=allow_r, timeout=15)
        else:
            resp = session.post(url, data=probe.get("data", {}),
                                allow_redirects=allow_r, timeout=15)
    except requests.exceptions.RequestException as exc:
        log.error("[%s/%s] request error: %s", module, level, exc)
        return {"status": 0, "length": 0, "has_error": True,
                "body_snippet": str(exc)}

    body    = resp.text
    has_err = bool(PHP_ERROR_RE.search(body))

    log.info("[%s/%s] %s %s → HTTP %d  len=%d  err=%s",
             module, level, method, probe["url"],
             resp.status_code, len(body), has_err)

    return {
        "status":       resp.status_code,
        "length":       len(body),
        "has_error":    has_err,
        "body_snippet": body[:500],
    }


# ── patch enumeration ──────────────────────────────────────────────────────────

def collect_patches() -> list[dict]:
    """
    Scan all three output directories and return a list of patch records:
      { layer, module, level, local_path, container_path }
    """
    patches = []
    for layer, base_dir in OUTPUT_DIRS.items():
        if not base_dir.exists():
            log.warning("Output dir missing: %s", base_dir)
            continue
        for php_file in sorted(base_dir.rglob("*.php")):
            parts = php_file.relative_to(base_dir).parts
            if len(parts) != 2:
                log.warning("Unexpected path shape: %s", php_file)
                continue
            module, filename = parts
            level = filename.replace(".php", "")
            if level not in ("low", "medium", "high"):
                log.warning("Skipping unexpected level file: %s", php_file)
                continue
            container_path = (
                f"{CONTAINER_VULN_BASE}/{module}/source/{level}.php"
            )
            patches.append({
                "layer":          layer,
                "module":         module,
                "level":          level,
                "local_path":     php_file,
                "container_path": container_path,
            })
    log.info("Found %d patched files across %d layers.", len(patches),
             len(OUTPUT_DIRS))
    return patches


# ── baseline phase ─────────────────────────────────────────────────────────────

def run_baseline(session: requests.Session, patches: list[dict]) -> dict:
    """
    For each unique (module, level) in patches, probe the unmodified DVWA.
    Returns { "module/level": result_dict }.
    """
    seen   = set()
    result = {}

    for p in patches:
        key = f"{p['module']}/{p['level']}"
        if key in seen:
            continue
        seen.add(key)
        log.info("BASELINE  %s", key)
        result[key] = probe_module(session, p["module"], p["level"])

    return result


# ── patched phase ──────────────────────────────────────────────────────────────

def run_patched(session: requests.Session, patches: list[dict]) -> list[dict]:
    """
    For each patch: backup original from container, install patch, probe, restore.
    Returns list of result records.
    """
    results = []
    tmp_dir = PROJECT_DIR / ".patch_tester_tmp"
    tmp_dir.mkdir(exist_ok=True)

    for idx, p in enumerate(patches, 1):
        module         = p["module"]
        level          = p["level"]
        layer          = p["layer"]
        local_patch    = p["local_path"]
        container_path = p["container_path"]
        key            = f"{layer}/{module}/{level}"

        log.info("PATCHED  [%d/%d]  %s", idx, len(patches), key)

        backup_local = tmp_dir / f"{layer}_{module}_{level}_original.php"

        try:
            # 1. back up original
            docker_cp_from_container(container_path, backup_local)
        except RuntimeError as exc:
            log.error("Backup failed for %s: %s", key, exc)
            results.append({
                "layer": layer, "module": module, "level": level,
                "status": -1, "length": 0, "has_error": True,
                "body_snippet": f"backup failed: {exc}",
                "error": str(exc),
            })
            continue

        try:
            # 2. install patch
            docker_cp_to_container(local_patch, container_path)

            # 3. probe
            result = probe_module(session, module, level)
            result.update({"layer": layer, "module": module, "level": level})
            results.append(result)

        except RuntimeError as exc:
            log.error("Patch install failed for %s: %s", key, exc)
            results.append({
                "layer": layer, "module": module, "level": level,
                "status": -1, "length": 0, "has_error": True,
                "body_snippet": f"install failed: {exc}",
                "error": str(exc),
            })

        finally:
            # 4. restore original unconditionally
            try:
                docker_cp_to_container(backup_local, container_path)
                log.info("Restored %s", container_path)
            except RuntimeError as exc2:
                log.error("RESTORE FAILED for %s: %s  — DVWA state may be dirty!", key, exc2)
            if backup_local.exists():
                backup_local.unlink()

    shutil.rmtree(tmp_dir, ignore_errors=True)
    return results


# ── verdict logic ──────────────────────────────────────────────────────────────

def compute_verdict(bl: dict, pt: dict) -> tuple[bool, str]:
    """
    Returns (new_error_introduced, verdict).
    PASS        – patched status == baseline status AND no new error.
    BROKEN      – patch introduced a PHP error OR returned a different HTTP status.
    INCONCLUSIVE – baseline itself had an error (cannot distinguish).
    """
    if bl["has_error"]:
        return False, "INCONCLUSIVE"

    new_err = pt["has_error"] and not bl["has_error"]
    status_changed = (pt["status"] != bl["status"]) and (pt["status"] not in (0, -1))

    if new_err or pt["status"] in (500,) or status_changed:
        return new_err, "BROKEN"

    if pt["status"] in (0, -1):
        return False, "INCONCLUSIVE"

    return False, "PASS"


# ── output writers ─────────────────────────────────────────────────────────────

def write_csv(patches: list[dict], baseline: dict, patched_results: list[dict]):
    patched_index = {}
    for r in patched_results:
        k = (r["layer"], r["module"], r["level"])
        patched_index[k] = r

    rows = []
    for p in patches:
        bl_key = f"{p['module']}/{p['level']}"
        bl     = baseline.get(bl_key, {})
        pt     = patched_index.get((p["layer"], p["module"], p["level"]), {})

        if not bl or not pt:
            verdict = "INCONCLUSIVE"
            new_err = False
        else:
            new_err, verdict = compute_verdict(bl, pt)

        rows.append({
            "layer":                p["layer"],
            "module":               p["module"],
            "level":                p["level"],
            "baseline_status":      bl.get("status", ""),
            "patched_status":       pt.get("status", ""),
            "baseline_length":      bl.get("length", ""),
            "patched_length":       pt.get("length", ""),
            "baseline_has_error":   bl.get("has_error", ""),
            "patched_has_error":    pt.get("has_error", ""),
            "new_error_introduced": new_err,
            "verdict":              verdict,
        })

    fieldnames = [
        "layer", "module", "level",
        "baseline_status", "patched_status",
        "baseline_length", "patched_length",
        "baseline_has_error", "patched_has_error",
        "new_error_introduced", "verdict",
    ]
    with open(RESULTS_CSV, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    log.info("Wrote %s (%d rows).", RESULTS_CSV, len(rows))
    return rows


def print_summary(rows: list[dict]):
    totals = {"PASS": 0, "BROKEN": 0, "INCONCLUSIVE": 0}
    broken_new_err = 0
    for r in rows:
        v = r["verdict"]
        totals[v] = totals.get(v, 0) + 1
        if v == "BROKEN" and r["new_error_introduced"]:
            broken_new_err += 1

    total = len(rows)
    print("\n" + "=" * 60)
    print(f"  PATCH REGRESSION SUMMARY  ({total} patches across 3 layers)")
    print("=" * 60)
    print(f"  PASS          : {totals['PASS']:>4}  ({100*totals['PASS']//max(total,1):>3}%)")
    print(f"  BROKEN        : {totals['BROKEN']:>4}  ({100*totals['BROKEN']//max(total,1):>3}%)")
    print(f"    of which new PHP errors introduced: {broken_new_err}")
    print(f"  INCONCLUSIVE  : {totals['INCONCLUSIVE']:>4}  ({100*totals['INCONCLUSIVE']//max(total,1):>3}%)")
    print("=" * 60)

    if totals["BROKEN"]:
        print("\nBROKEN patches:")
        for r in rows:
            if r["verdict"] == "BROKEN":
                new_e = " [new error]" if r["new_error_introduced"] else ""
                print(f"  {r['layer']:2}  {r['module']:20}  {r['level']:6}"
                      f"  baseline={r['baseline_status']}  patched={r['patched_status']}"
                      f"{new_e}")
    print()


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    global CONTAINER

    parser = argparse.ArgumentParser(description="DVWA patch regression tester")
    parser.add_argument("--skip-docker", action="store_true",
                        help="Skip docker compose up (DVWA already running)")
    args = parser.parse_args()

    log.info("=== patch_tester.py started at %s ===", datetime.now().isoformat())

    # ── step 1: docker ───────────────────────────────────────────────────────
    if not args.skip_docker:
        docker_start()

    CONTAINER = detect_container()
    log.info("Using container: %s", CONTAINER)

    wait_for_dvwa()

    session = requests.Session()
    dvwa_setup(session)
    dvwa_login(session)

    # ── step 2: enumerate patches ────────────────────────────────────────────
    patches = collect_patches()
    if not patches:
        log.error("No patch files found. Check OUTPUT_DIRS paths.")
        sys.exit(1)

    # ── step 3: baseline ─────────────────────────────────────────────────────
    log.info("=== BASELINE PHASE ===")
    baseline = run_baseline(session, patches)
    BASELINE_JSON.write_text(json.dumps(baseline, indent=2))
    log.info("Wrote %s.", BASELINE_JSON)

    # ── step 4: patched ──────────────────────────────────────────────────────
    log.info("=== PATCHED PHASE ===")
    patched_results = run_patched(session, patches)
    PATCHED_JSON.write_text(json.dumps(patched_results, indent=2))
    log.info("Wrote %s.", PATCHED_JSON)

    # ── step 5: results.csv + summary ────────────────────────────────────────
    rows = write_csv(patches, baseline, patched_results)
    print_summary(rows)

    log.info("=== Done. Full request log: %s ===", LOG_FILE)


if __name__ == "__main__":
    main()
