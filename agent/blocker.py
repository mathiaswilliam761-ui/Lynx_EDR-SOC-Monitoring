#!/usr/bin/env python3
"""Blocker — denies an attacker by IP and MAC using nftables (or iptables)."""

from __future__ import annotations

import shutil
import subprocess


class Blocker:
    def __init__(self, cfg: dict, ledger, logger):
        self.cfg = cfg.get("blocking", {})
        self.ledger = ledger
        self.log = logger
        self.enabled = self.cfg.get("enabled", True)
        self.backend = self.cfg.get("backend", "nftables")
        self.table = self.cfg.get("table_name", "lynx_block")
        self.dry_run = self.cfg.get("dry_run", False)
        self._blocked = set()
        # Verify the chosen backend exists.
        if self.backend == "nftables" and not shutil.which("nft"):
            self.log.warning("nft not found; falling back to iptables")
            self.backend = "iptables"
        if self.backend == "iptables" and not shutil.which("iptables"):
            self.log.warning("iptables not found; blocking will be DRY-RUN only")
            self.dry_run = True

    def _ensure_table(self):
        if self.backend != "nftables" or self.dry_run:
            return
        # Create table (idempotent) if not present.
        subprocess.run(["nft", "list", "table", "inet", self.table],
                       capture_output=True)
        subprocess.run(["nft", "add", "table", "inet", self.table],
                       capture_output=True)
        subprocess.run(["nft", "add", "chain", "inet", self.table, "input",
                        "{ type filter hook input priority 0; }"],
                       capture_output=True)
        subprocess.run(["nft", "add", "chain", "inet", self.table, "output",
                        "{ type filter hook output priority 0; }"],
                       capture_output=True)

    def block(self, ip: str | None, mac: str | None, reason: str) -> bool:
        if not self.enabled:
            return False
        key = (ip or "", mac or "")
        if key in self._blocked:
            return False
        self._blocked.add(key)
        self._ensure_table()

        if self.dry_run:
            self.log.info("DRY-RUN block: ip=%s mac=%s (%s)", ip, mac, reason)
        elif self.backend == "nftables":
            if ip:
                r = subprocess.run(
                    ["nft", "add", "rule", "inet", self.table, "input",
                     "ip", "saddr", ip, "drop"], capture_output=True, text=True)
                self.log.info("nft block ip=%s rc=%s", ip, r.returncode)
            if mac:
                r = subprocess.run(
                    ["nft", "add", "rule", "inet", self.table, "input",
                     "ether", "saddr", mac, "drop"], capture_output=True, text=True)
                self.log.info("nft block mac=%s rc=%s", mac, r.returncode)
        elif self.backend == "iptables":
            if ip:
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                               capture_output=True)
            if mac:
                subprocess.run(["iptables", "-A", "INPUT", "-m", "mac",
                                "--mac-source", mac, "-j", "DROP"],
                               capture_output=True)

        self.ledger.record_block(ip, mac, reason, self.backend)
        self.ledger.record("block", {"ip": ip, "mac": mac, "reason": reason,
                                     "backend": self.backend},
                           severity="critical", source="blocker")
        self.log.warning("BLOCKED ip=%s mac=%s (%s) via %s",
                         ip, mac, reason, self.backend)
        return True