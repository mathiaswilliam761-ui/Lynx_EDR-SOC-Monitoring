#!/usr/bin/env bash
# Lynx EDR — one-shot installer.
# Installs dependencies, checks for optional tools (nft/iptables), and prints next steps.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "== Lynx EDR installer =="
echo "Install dir: $DIR"

# Python interpreter (prefer a venv if present)
PY=python3
if [ -d "$DIR/.venv" ]; then
    PY="$DIR/.venv/bin/python"
fi
echo "Python: $($PY --version 2>&1)"

echo "== Installing Python deps =="
$PY -m pip install -r "$DIR/requirements.txt" 2>/dev/null \
    || echo "(pip unavailable; PyYAML may already be present — verify below)"

echo "== Checking optional system tools =="
for tool in nft iptables tcpdump scapy; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "  [OK]   $tool"
    else
        echo "  [skip] $tool (optional)"
    fi
done

echo ""
echo "== Next steps =="
echo "1. Edit $DIR/configs/agent.yaml to set watched dirs, network options, and alerting."
echo "2. Start the agent (root recommended for nftables blocking + /proc/all log access):"
echo "     sudo $PY -m agent.main run"
echo "3. Test detection:"
echo "     sudo $PY -m agent.main status"
echo "     $PY $DIR/scripts/simulate_attack.py"
echo "4. Generate a report:"
echo "     $PY -m agent.main report"
echo ""
echo "Done."