#!/usr/bin/env python3
"""Process monitor — polls /proc for suspicious processes and high CPU."""

from __future__ import annotations

import os
import re


class ProcessMonitor:
    def __init__(self, cfg: dict, ledger, logger):
        self.cfg = cfg.get("process_monitor", {})
        self.ledger = ledger
        self.log = logger
        self.enabled = self.cfg.get("enabled", True)
        self.suspicious = [n.lower() for n in self.cfg.get("suspicious_names", [])]
        self.cpu_threshold = self.cfg.get("high_cpu_threshold", 90.0)
        self._seen = set()
        self._cpu_prev = {}   # pid -> accumulated jiffies
        self._cpu_prev_time = 0

    def _list_procs(self) -> dict:
        procs = {}
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/comm") as f:
                    comm = f.read().strip()
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmdline = f.read().replace(b"\x00", b" ").decode(errors="ignore").strip()
                procs[int(pid)] = (comm, cmdline)
            except (OSError, IOError):
                continue
        return procs

    def _proc_cpu(self, pid: int) -> float | None:
        try:
            with open(f"/proc/{pid}/stat") as f:
                fields = f.read().split()
            utime = int(fields[13]); stime = int(fields[14])
            return utime + stime
        except (OSError, ValueError, IndexError):
            return None

    def sweep(self) -> list[dict]:
        if not self.enabled:
            return []
        alerts = []
        procs = self._list_procs()
        for pid, (comm, cmdline) in procs.items():
            low = (comm + " " + cmdline).lower()
            if any(s in low for s in self.suspicious):
                alerts.append({"type": "process", "pid": pid, "comm": comm,
                               "cmdline": cmdline, "reason": "suspicious_name"})
                self.ledger.record("process",
                                   {"pid": pid, "comm": comm, "cmdline": cmdline,
                                    "reason": "suspicious_name"},
                                   severity="high", source="process_monitor")
                self.log.warning("SUSPICIOUS PROC: %s (pid %d)", comm, pid)
        self._seen = set(procs)
        return alerts