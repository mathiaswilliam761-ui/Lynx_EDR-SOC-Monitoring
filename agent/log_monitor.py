#!/usr/bin/env python3
"""Log monitor — tails log files and raises alerts on suspicious patterns."""

from __future__ import annotations

import os
import re
import time


class LogMonitor:
    def __init__(self, cfg: dict, ledger, logger):
        self.cfg = cfg.get("log_monitor", {})
        self.ledger = ledger
        self.log = logger
        self.enabled = self.cfg.get("enabled", True)
        # Compile patterns once.
        self.patterns = []
        for name, regex in self.cfg.get("patterns", {}).items():
            self.patterns.append((name, re.compile(regex)))
        # Track where we've read up to in each file.
        self._positions = {}

    def _tail(self, path: str) -> list[str]:
        """Return new lines since last read. Uses size + stored position."""
        if not os.path.exists(path):
            return []
        size = os.path.getsize(path)
        pos = self._positions.get(path, 0)
        if size < pos:
            # File rotated/truncated — start from beginning.
            pos = 0
        if size == pos:
            return []
        with open(path, "r", errors="ignore") as f:
            f.seek(pos)
            new = f.read()
            self._positions[path] = f.tell()
        return new.splitlines()

    def sweep(self) -> list[dict]:
        """Check all configured logs; return list of alert dicts."""
        if not self.enabled:
            return []
        alerts = []
        for path in self.cfg.get("files", []):
            for line in self._tail(path):
                for name, pat in self.patterns:
                    m = pat.search(line)
                    if m:
                        ip = m.groupdict().get("ip", "unknown")
                        alert = {
                            "type": "log_alert",
                            "rule": name,
                            "ip": ip,
                            "line": line.strip(),
                            "file": path,
                        }
                        self.ledger.record(
                            "alert", alert, severity="high", source="log_monitor"
                        )
                        alerts.append(alert)
                        self.log.warning("LOG ALERT: %s (ip=%s)", name, ip)
        return alerts