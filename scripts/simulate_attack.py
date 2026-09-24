#!/usr/bin/env python3
"""
Attack simulator — triggers controlled, safe suspicious activity so you can verify the
agent detects, blocks, and backs up WITHOUT needing a second machine or real malware.

Run this and watch `python3 -m agent.main` (or the ledger) react.

Actions (all safe, local, reversible):
    1. Simulate a brute-force attempt by writing failed-login lines to a test log.
    2. Create + modify + delete files under a watched directory (FIM + backup).
    3. Spawn a process with a "suspicious" name (process monitor).
    4. Open several quick connections to localhost:22-ish ports (IDS scan heuristic).

Usage:
    python3 scripts/simulate_attack.py [--log /var/log/auth.log.test]
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time


def simulate_bruteforce(log_path: str):
    lines = [
        "Aug 31 15:00:01 host sshd[123]: Failed password for root from 203.0.113.55 port 44122 ssh2",
        "Aug 31 15:00:02 host sshd[123]: Failed password for invalid user admin from 203.0.113.55 port 44123 ssh2",
        "Aug 31 15:00:03 host sshd[123]: Failed password for root from 203.0.113.55 port 44124 ssh2",
    ]
    with open(log_path, "a") as f:
        for l in lines:
            f.write(l + "\n")
    print(f"[*] Wrote simulated SSH brute-force to {log_path} (attacker 203.0.113.55)")


def simulate_file_activity(d):
    os.makedirs(d, exist_ok=True)
    fp = os.path.join(d, "sensitive_data.txt")
    with open(fp, "w") as f:
        f.write("original content")
    time.sleep(0.1)
    with open(fp, "w") as f:  # modify
        f.write("MODIFIED by attacker (simulated)")
    time.sleep(0.1)
    os.remove(fp)  # delete
    print(f"[*] File create/modify/delete simulated in {d}")


def simulate_suspicious_process():
    # Spawn a harmless sleep process but name its comm 'xmrminer-like'.
    p = subprocess.Popen(["bash", "-c", "exec -a xmrminer0 sleep 30"])
    print(f"[*] Spawned 'suspicious' process pid={p.pid} (name xmrminer0)")
    return p


def simulate_port_scan(host="127.0.0.1", ports=(22, 23, 80, 443, 445, 3389, 8080, 8443)):
    print("[*] Simulating port scan connections ...")
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect_ex((host, p))
            s.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="/tmp/auth.log.test")
    ap.add_argument("--dir", default="/tmp/watch_test")
    args = ap.parse_args()

    print("=== Lynx attack simulator ===")
    simulate_bruteforce(args.log)
    simulate_file_activity(args.dir)
    proc = simulate_suspicious_process()
    simulate_port_scan()
    print("[*] Simulation complete. Check `python3 -m agent.main status` / report.")
    # Leave the suspicious process running briefly so the monitor can catch it.
    time.sleep(2)
    proc.terminate()


if __name__ == "__main__":
    main()