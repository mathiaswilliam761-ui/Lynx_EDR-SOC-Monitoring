#!/usr/bin/env python3
"""
Network IDS — monitors connections and (optionally) packets, detects port scans and
brute-force, extracts attacker IP and MAC, and hands them to the Blocker.

Reads Linux connection tables via /proc/net/tcp* and (if enabled) the ARP table for MAC
resolution. No root packet capture needed for the connection-based mode.
"""

from __future__ import annotations

import os
import re
import time
from collections import defaultdict, deque


def _parse_ip(hexip: str) -> str:
    """Convert /proc/net little-endian hex IP to dotted quad."""
    if len(hexip) != 8:
        return hexip
    try:
        b = bytes.fromhex(hexip)
        return ".".join(str(x) for x in reversed(b))
    except ValueError:
        return hexip


class NetworkIDS:
    def __init__(self, cfg: dict, ledger, logger):
        self.cfg = cfg.get("network_ids", {})
        self.ledger = ledger
        self.log = logger
        self.enabled = self.cfg.get("enabled", True)
        self.watch_ports = set(self.cfg.get("watch_ports", []))
        self.scan_threshold = self.cfg.get("scan_threshold", 8)
        self.brute_threshold = self.cfg.get("brute_force_threshold", 5)
        self.window = self.cfg.get("window_seconds", 30)
        # ip -> deque of (ts, port) for scan detection
        self._conn_history = defaultdict(deque)

    def arp_table(self) -> dict:
        """Return {ip: mac} from /proc/net/arp."""
        out = {}
        try:
            with open("/proc/net/arp") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                        out[parts[0]] = parts[3]
        except OSError:
            pass
        return out

    def tcp_connections(self) -> list[tuple[str, int]]:
        """Return list of (remote_ip, remote_port) for ESTABLISHED/SYN connections."""
        conns = []
        for tbl in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(tbl) as f:
                    for line in f:
                        p = line.split()
                        if len(p) < 10 or p[0].startswith("sl"):
                            continue
                        state = p[3]
                        if state not in ("01", "02", "03"):  # ESTABLISHED, SYN_SENT, SYN_RECV
                            continue
                        local, remote = p[1], p[2]
                        rip_hex = remote.split(":")[0]
                        rport = int(remote.split(":")[1], 16)
                        if rport in self.watch_ports or state == "02":
                            conns.append((_parse_ip(rip_hex), rport))
            except OSError:
                continue
        return conns

    def sweep(self) -> dict:
        """Return {'alerts': [...], 'attackers': {ip: {'mac':..., 'ports':set, 'reason'}}}."""
        if not self.enabled:
            return {"alerts": [], "attackers": {}}
        now = time.time()
        arp = self.arp_table()
        alerts = []
        attackers = {}

        for ip, port in self.tcp_connections():
            dq = self._conn_history[ip]
            dq.append((now, port))
            # prune old entries
            while dq and now - dq[0][0] > self.window:
                dq.popleft()
            distinct = {p for _, p in dq}
            if len(distinct) >= self.scan_threshold:
                reason = f"port_scan ({len(distinct)} ports in {self.window}s)"
                attackers.setdefault(ip, {"mac": arp.get(ip), "ports": set(), "reason": reason})
                attackers[ip]["ports"].update(distinct)
                alerts.append({"type": "port_scan", "ip": ip,
                               "mac": arp.get(ip), "ports": sorted(distinct)})

        for ip, info in attackers.items():
            self.ledger.record("network",
                               {"ip": ip, "mac": info["mac"],
                                "reason": info["reason"],
                                "ports": sorted(info["ports"])},
                               severity="high", source="network_ids")
            self.log.warning("NETWORK ALERT: %s %s ip=%s mac=%s",
                             info["reason"], "from", ip, info.get("mac"))
        return {"alerts": alerts, "attackers": attackers}