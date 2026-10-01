"""
dast_framework/core/docker_runner.py
=====================================
Runs DVWA + MySQL using plain docker commands (no docker-compose needed).

DVWA requires MySQL. Previous version ran DVWA alone, causing:
  mysqli_sql_exception: Connection refused on port 3306

Fix: start MySQL container first, wait for it to be healthy,
then start DVWA linked to MySQL on the same Docker network.
Also initialises the DVWA database via setup.php automatically.
"""

import subprocess
import time
import os
import urllib.request
import urllib.parse
import requests

APP_PORT        = 8080
NETWORK_NAME    = "dast-scan-net"
CONTAINER_NAME  = "dast-target-container"
MYSQL_CONTAINER = "dvwa-mysql"
ZAP_CONTAINER   = "zap-daemon"
ZAP_HOST_PORT   = 8081
INTERNAL_PORT   = 80


def _ensure_network():
    existing = subprocess.run(
        ["docker", "network", "ls", "--format", "{{.Name}}"],
        capture_output=True, text=True
    ).stdout.splitlines()
    if NETWORK_NAME not in existing:
        subprocess.run(["docker", "network", "create", NETWORK_NAME], check=True)
        print(f"[*] Created Docker network: {NETWORK_NAME}")
    else:
        print(f"[*] Using existing Docker network: {NETWORK_NAME}")


def _stop_existing():
    subprocess.run(["docker", "rm", "-f", CONTAINER_NAME, MYSQL_CONTAINER],
                   capture_output=True)


def _start_mysql():
    print("[*] Starting MySQL container...")
    subprocess.check_output([
        "docker", "run", "-d",
        "--name", MYSQL_CONTAINER,
        "--network", NETWORK_NAME,
        "-e", "MYSQL_ROOT_PASSWORD=rootpassword",
        "-e", "MYSQL_DATABASE=dvwa",
        "-e", "MYSQL_USER=dvwa",
        "-e", "MYSQL_PASSWORD=p@ssw0rd",
        "mysql:8.0",
        "--default-authentication-plugin=mysql_native_password",
    ], text=True)

    print("[*] Waiting for MySQL to be ready (~20s)...")
    for attempt in range(24):  # 24 x 5s = 2 min max
        result = subprocess.run(
            ["docker", "exec", MYSQL_CONTAINER,
             "mysqladmin", "ping", "-h", "localhost",
             "-u", "dvwa", "-pp@ssw0rd", "--silent"],
            capture_output=True
        )
        if result.returncode == 0:
            print(f"[*] MySQL ready (attempt {attempt + 1})")
            return True
        time.sleep(5)
        print(f"[*] MySQL not ready yet ({attempt + 1}/24)...")

    print("[!] MySQL did not become ready in time")
    return False


def _start_zap():
    print("[*] Starting ZAP daemon...")
    subprocess.run(["docker", "rm", "-f", ZAP_CONTAINER], capture_output=True)
    subprocess.check_output([
        "docker", "run", "-d",
        "--name", ZAP_CONTAINER,
        "--network", "host",
        "ghcr.io/zaproxy/zaproxy:stable",
        "zap.sh", "-daemon",
        "-host", "127.0.0.1",   # loopback only — keeps proxy off external interfaces
        "-port", str(ZAP_HOST_PORT),
        "-config", "api.key=65a06u0hrv0l02utnag55lgeh7",
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.regex=true",
    ], text=True)

    print("[*] Waiting for ZAP to be ready (~30s)...")
    for attempt in range(40):
        try:
            r = requests.get(
                f"http://127.0.0.1:{ZAP_HOST_PORT}/JSON/core/view/version/",
                params={"apikey": "65a06u0hrv0l02utnag55lgeh7"},
                timeout=5,
            )
            if r.status_code == 200:
                print(f"[*] ZAP daemon ready (attempt {attempt + 1})")
                return True
        except Exception:
            pass
        time.sleep(5)

    print("[!] ZAP daemon did not become ready in time")
    return False


def build_and_run(repo):
    repo = os.path.abspath(repo)
    _ensure_network()
    _stop_existing()

    # Step 1: Start MySQL
    if not _start_mysql():
        raise RuntimeError("MySQL failed to start")

    # Step 2: Build DVWA image, falling back to the pre-pulled official image
    # if the local build fails (the Dockerfile runs `composer install` which
    # requires internet access and fails when DNS is unavailable in the build env).
    PREBUILT_IMAGE = "ghcr.io/digininja/dvwa:latest"
    image_name = "dast-target"
    print("[*] Building DVWA image...")
    build_result = subprocess.run(
        ["docker", "build", "-t", image_name, repo],
        capture_output=False
    )
    if build_result.returncode != 0:
        prebuilt_check = subprocess.run(
            ["docker", "image", "inspect", PREBUILT_IMAGE],
            capture_output=True
        )
        if prebuilt_check.returncode == 0:
            print(f"[!] Local build failed — falling back to {PREBUILT_IMAGE}")
            image_name = PREBUILT_IMAGE
        else:
            raise RuntimeError("Docker build failed and pre-built image not available locally")

    print("[*] Starting DVWA container...")
    cid = subprocess.check_output([
        "docker", "run", "-d",
        "--name", CONTAINER_NAME,
        "--network", NETWORK_NAME,
        "-p", f"{APP_PORT}:{INTERNAL_PORT}",
        "-e", "DISABLE_AUTHENTICATION=true",
        "-e", "DEFAULT_SECURITY_LEVEL=low",
        "-e", "DB_SERVER=dvwa-mysql",
        "-e", "DB_DATABASE=dvwa",
        "-e", "DB_USER=dvwa",
        "-e", "DB_PASSWORD=p@ssw0rd",
        image_name
    ], text=True).strip()

    print(f"[*] DVWA started — waiting for Apache to be ready...")
    time.sleep(10)

    for attempt in range(10):
        try:
            urllib.request.urlopen(f"http://localhost:{APP_PORT}", timeout=5)
            print(f"[*] DVWA reachable at http://localhost:{APP_PORT}")
            break
        except Exception:
            if attempt < 9:
                print(f"[*] Not ready ({attempt + 1}/10)...")
                time.sleep(5)
            else:
                print("[!] DVWA may not be fully ready")

    # Step 3: Initialise database via setup.php
    print("[*] Initialising DVWA database via setup.php...")
    time.sleep(3)
    try:
        data = urllib.parse.urlencode(
            {"create_db": "Create / Reset Database"}
        ).encode()
        req = urllib.request.Request(
            f"http://localhost:{APP_PORT}/setup.php",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        urllib.request.urlopen(req, timeout=20)
        print("[*] Database initialised successfully")
        time.sleep(3)
    except Exception as e:
        print(f"[*] DB init: {e}")

    # Step 4: Start ZAP daemon
    if not _start_zap():
        raise RuntimeError("ZAP daemon failed to start")

    return {
        "container_id": cid,
        "host_url":     f"http://localhost:{APP_PORT}",
        "container_url": f"http://{CONTAINER_NAME}:{INTERNAL_PORT}",
    }