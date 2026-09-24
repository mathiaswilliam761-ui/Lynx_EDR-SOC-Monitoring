#!/usr/bin/env python3
"""Report generator — produces an incident summary (Markdown + JSON) from the ledger."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone


class Reporter:
    def __init__(self, ledger, install_dir: str, logger):
        self.ledger = ledger
        self.log = logger
        self.out_dir = os.path.join(install_dir, "logs")

    def report(self, since_hours: int = 24) -> str:
        rows_alerts = self.ledger.query(
            "SELECT ts, severity, source, detail FROM events "
            "WHERE event_type='alert' ORDER BY id DESC LIMIT 500")
        rows_blocks = self.ledger.query(
            "SELECT ts, ip, mac, reason, backend FROM blocks ORDER BY id DESC LIMIT 200")
        rows_versions = self.ledger.query(
            "SELECT count(*) c FROM file_versions")
        rows_custody = self.ledger.query(
            "SELECT count(*) c FROM chain_custody")

        lines = []
        lines.append("# Lynx EDR — Incident Report")
        lines.append("")
        lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
        lines.append("")
        lines.append("## Summary")
        lines.append(f"- Alerts: {len(rows_alerts)}")
        lines.append(f"- Blocks: {len(rows_blocks)}")
        lines.append(f"- File versions tracked: {rows_versions[0]['c'] if rows_versions else 0}")
        lines.append(f"- Artifacts hashed (CoC): {rows_custody[0]['c'] if rows_custody else 0}")
        lines.append("")

        lines.append("## Blocked attackers")
        if rows_blocks:
            for b in rows_blocks:
                lines.append(f"- `{b['ts']}` ip={b['ip']} mac={b['mac']} "
                             f"reason={b['reason']} backend={b['backend']}")
        else:
            lines.append("(none)")
        lines.append("")

        lines.append("## Alerts (recent first)")
        if rows_alerts:
            for a in rows_alerts:
                lines.append(f"- `{a['ts']}` [{a['severity']}] {a['source']}: {a['detail']}")
        else:
            lines.append("(none)")
        lines.append("")

        md = "\n".join(lines)
        os.makedirs(self.out_dir, exist_ok=True)
        path = os.path.join(self.out_dir, "incident_report.md")
        with open(path, "w") as f:
            f.write(md)
        self.log.info("Report written to %s", path)
        return md