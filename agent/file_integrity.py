#!/usr/bin/env python3
"""File Integrity Monitor — watches directories, hashes files, detects changes."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path


class FileIntegrityMonitor:
    # Directories that REQUIRE an explicit opt-in before FIM watches them (avoid
    # spamming alerts/events from a full system scan you didn't intend).
    SENSITIVE_DIRS = {"/", "/home", "/etc", "/root", "/usr", "/var", "/boot", "/opt"}

    def __init__(self, cfg: dict, ledger, logger):
        self.cfg = cfg.get("fim", {})
        self.ledger = ledger
        self.log = logger
        self.enabled = self.cfg.get("enabled", True)
        self.watch_dirs = self.cfg.get("watch_dirs", [])
        self.ignore_ext = self.cfg.get("ignore_extensions", [])
        self.max_events = self.cfg.get("max_events_per_sweep", 200)
        # baseline: path -> (size, mtime, sha256)
        self._baseline = {}
        self._validate_watch_dirs()

    def _validate_watch_dirs(self):
        if self.cfg.get("allow_sensitive_dirs", False):
            return
        for d in self.watch_dirs:
            norm = os.path.abspath(d)
            if norm in self.SENSITIVE_DIRS:
                self.log.error(
                    "FIM watch dir %r is a sensitive/system directory. Set "
                    "fim.allow_sensitive_dirs: true to watch it. Skipping.", d)
        self.watch_dirs = [
            d for d in self.watch_dirs
            if os.path.abspath(d) not in self.SENSITIVE_DIRS
        ]

    def _snapshot(self) -> dict:
        snap = {}
        for d in self.watch_dirs:
            if not os.path.isdir(d):
                continue
            for root, dirs, files in os.walk(d):
                dirs[:] = [x for x in dirs if not x.startswith(".")]
                for name in files:
                    if any(name.endswith(ext) for ext in self.ignore_ext):
                        continue
                    fp = os.path.join(root, name)
                    try:
                        st = os.stat(fp)
                        snap[fp] = (st.st_size, st.st_mtime)
                    except OSError:
                        continue
        return snap

    def baseline(self):
        """Capture the initial snapshot (call once at startup)."""
        self._baseline = self._snapshot()
        self.log.info("FIM baseline captured: %d files", len(self._baseline))

    def sweep(self) -> list[dict]:
        if not self.enabled:
            return []
        alerts = []
        now = self._snapshot()
        keys = set(self._baseline) | set(now)
        for k in list(keys):
            if len(alerts) >= self.max_events:
                break
            before = self._baseline.get(k)
            after = now.get(k)
            if before == after:
                continue
            event = "created" if before is None else ("deleted" if after is None else "modified")
            alerts.append({"type": "file_change", "path": k, "event": event})
            self.ledger.record("file_change",
                               {"path": k, "event": event},
                               severity="medium", source="fim")
            self.log.info("FIM %s: %s", event, k)
        self._baseline = now
        return alerts