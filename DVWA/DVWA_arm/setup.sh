#!/usr/bin/env bash
# setup.sh — Install all dependencies for the CVE Scanner Framework
# Run once before your first scan: bash setup.sh

set -e
echo "============================================================"
echo "  CVE Scanner Framework — Dependency Setup"
echo "============================================================"

# Python deps
echo "[*] Installing Python dependencies..."
pip install bandit flawfinder semgrep --break-system-packages 2>/dev/null || \
pip install bandit flawfinder semgrep --user

# ffuf
if ! command -v ffuf &>/dev/null; then
    echo "[*] Installing ffuf..."
    if command -v go &>/dev/null; then
        go install github.com/ffuf/ffuf/v2@latest
    elif command -v apt-get &>/dev/null; then
        sudo apt-get install -y ffuf
    else
        echo "[!] Install ffuf manually: https://github.com/ffuf/ffuf/releases"
    fi
else
    echo "[+] ffuf already installed: $(ffuf -V 2>&1 | head -1)"
fi

# semgrep check
if command -v semgrep &>/dev/null; then
    echo "[+] semgrep installed: $(semgrep --version)"
else
    echo "[!] semgrep not found — trying pip3..."
    pip3 install semgrep --break-system-packages 2>/dev/null || pip3 install semgrep --user
fi

# Docker check
if command -v docker &>/dev/null; then
    echo "[+] Docker available"
else
    echo "[!] Docker not found — DAST scanning requires Docker"
fi

# Pre-pull Docker images
echo "[*] Pulling Docker images (ZAP, Nuclei)..."
docker pull ghcr.io/zaproxy/zaproxy:stable &
docker pull projectdiscovery/nuclei &
wait
echo "[+] Docker images ready"

echo ""
echo "============================================================"
echo "  Setup complete. Run your scan with:"
echo "  python3 run_scan.py --all ./DVWA"
echo "============================================================"
