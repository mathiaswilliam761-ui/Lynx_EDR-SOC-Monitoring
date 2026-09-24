#!/usr/bin/env python3
"""
Lynx EDR — main agent loop.

Spawns one thread per detection module plus a CLI for control. The main loop:
    every poll_interval seconds, sweep all detectors, aggregate alerts,
    block attackers, and forward alerts.

Usage:
    sudo python3 -m agent.main            # run the agent (foreground)
    sudo python3 -m agent.main report     # print incident report
    sudo python3 -m agent.main status     # print ledger summary
"""

from __future__ import annotations

import os
import sys
import time

# Ensure the parent dir is on sys.path so `agent.*` imports work.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.ledger import Ledger, load_config, setup_logging, INSTALL_DIR  # noqa: E402
from agent.log_monitor import LogMonitor  # noqa: E402
from agent.file_integrity import FileIntegrityMonitor  # noqa: E402
from agent.process_monitor import ProcessMonitor  # noqa: E402
from agent.network_ids import NetworkIDS  # noqa: E402
from agent.blocker import Blocker  # noqa: E402
from agent.backup import Backup  # noqa: E402
from agent.alerter import Alerter  # noqa: E402
from agent.reporter import Reporter  # noqa: E402
from agent.dashboard import start_dashboard  # noqa: E402


def build_components(cfg):
    logger = setup_logging(cfg["agent"].get("log_level", "INFO"))
    ledger = Ledger(os.path.join(INSTALL_DIR, cfg["ledger"]["db_path"]))
    modules = {
        "log_monitor": LogMonitor(cfg, ledger, logger),
        "fim": FileIntegrityMonitor(cfg, ledger, logger),
        "process": ProcessMonitor(cfg, ledger, logger),
        "network": NetworkIDS(cfg, ledger, logger),
        "blocker": Blocker(cfg, ledger, logger),
        "backup": Backup(cfg, ledger, INSTALL_DIR, logger),
        "alerter": Alerter(cfg, INSTALL_DIR, logger),
        "reporter": Reporter(ledger, INSTALL_DIR, logger),
    }
    return ledger, logger, modules


def run_loop(cfg):
    ledger, logger, m = build_components(cfg)
    interval = cfg["agent"].get("poll_interval", 2)

    logger.info("Lynx EDR starting (poll=%ss)", interval)
    m["fim"].baseline()

    # Start the web dashboard (if enabled) alongside the detection loop.
    httpd = None
    if cfg.get("web", {}).get("enabled", False):
        httpd = start_dashboard(ledger, m["backup"], m["reporter"], cfg, logger)

    try:
        while True:
            alerts = []
            alerts += m["log_monitor"].sweep()
            alerts += m["fim"].sweep()
            alerts += m["process"].sweep()
            net = m["network"].sweep()

            # Block detected attackers (IP + MAC).
            for ip, info in net["attackers"].items():
                m["blocker"].block(ip, info.get("mac"), info["reason"])
            for a in net["alerts"]:
                alerts.append(a)

            # Continuous backup.
            m["backup"].sweep()

            # Forward alerts.
            for a in alerts:
                m["alerter"].alert(a)

            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Shutting down.")
    finally:
        ledger.close()


def cmd_report(cfg):
    ledger, logger, m = build_components(cfg)
    print(m["reporter"].report())
    ledger.close()


def cmd_status(cfg):
    ledger, logger, _ = build_components(cfg)
    events = ledger.query("SELECT event_type, severity, count(*) c FROM events GROUP BY 1,2")
    blocks = ledger.query("SELECT count(*) c FROM blocks WHERE active=1")
    versions = ledger.query("SELECT count(*) c FROM file_versions")
    print("Lynx EDR status")
    print("-" * 40)
    for e in events:
        print(f"  {e['event_type']:12s} {e['severity']:8s} = {e['c']}")
    print(f"  active blocks   = {blocks[0]['c'] if blocks else 0}")
    print(f"  file versions   = {versions[0]['c'] if versions else 0}")
    ledger.close()


def cmd_restore(cfg):
    """Restore a file from its latest (or a specific) backed-up version."""
    if len(sys.argv) < 3:
        print("Usage: python -m agent.main restore <path> [--version <version_path>]")
        sys.exit(1)
    ledger, logger, m = build_components(cfg)
    orig = sys.argv[2]
    version_path = None
    if "--version" in sys.argv:
        version_path = sys.argv[sys.argv.index("--version") + 1]
    try:
        if version_path is None:
            rows = m["backup"].list_versions(orig)
            if not rows:
                print(f"No backup versions found for: {orig}")
            else:
                print(f"{len(rows)} version(s) found for {orig}:")
                for r in rows:
                    print(f"  [{r['id']}] {r['ts']}  {r['event']:8s}  {r['sha256'][:12]}…")
                resp = input("Restore latest version? [y/N] ").strip().lower()
                if resp in ("y", "yes"):
                    m["backup"].restore(orig)
                    print(f"✅ Restored {orig} from latest version.")
                else:
                    print("Aborted. Use --version <path> to pick a specific version.")
        else:
            m["backup"].restore(orig, version_path)
            print(f"✅ Restored {orig} from {version_path}")
    finally:
        ledger.close()


def main():
    cfg = load_config()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "run":
        run_loop(cfg)
    elif cmd == "report":
        cmd_report(cfg)
    elif cmd == "status":
        cmd_status(cfg)
    elif cmd == "restore":
        cmd_restore(cfg)
    else:
        print(f"Unknown command: {cmd}. Use: run | report | status | restore")


if __name__ == "__main__":
    main()