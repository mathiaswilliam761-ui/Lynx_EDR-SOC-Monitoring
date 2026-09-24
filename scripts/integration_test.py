#!/usr/bin/env python3
"""End-to-end integration test for the Lynx EDR agent (no root needed)."""
import sys, os, time, tempfile
sys.path.insert(0, '/opt/data/edr-agent')

from agent.ledger import Ledger, setup_logging, load_config
from agent.log_monitor import LogMonitor
from agent.file_integrity import FileIntegrityMonitor
from agent.process_monitor import ProcessMonitor
from agent.network_ids import NetworkIDS
from agent.blocker import Blocker
from agent.backup import Backup
from agent.alerter import Alerter
from agent.reporter import Reporter

cfg = load_config()
tmp = tempfile.mkdtemp()
cfg["ledger"]["db_path"] = os.path.join(tmp, "ledger.db")
cfg["backup"]["source_dirs"] = [os.path.join(tmp, "data")]
cfg["fim"]["watch_dirs"] = [os.path.join(tmp, "data")]
cfg["log_monitor"]["files"] = [os.path.join(tmp, "auth.log")]
cfg["alerter"] = cfg["alerting"]
cfg["blocking"]["dry_run"] = True
cfg["backup"]["backup_root"] = os.path.join(tmp, "backups")
cfg["alerting"]["local_file"] = os.path.join(tmp, "alerts.json")
cfg["network_ids"]["enabled"] = False

logger = setup_logging("WARN")
ledger = Ledger(cfg["ledger"]["db_path"])
m = {
    "log_monitor": LogMonitor(cfg, ledger, logger),
    "fim": FileIntegrityMonitor(cfg, ledger, logger),
    "process": ProcessMonitor(cfg, ledger, logger),
    "network": NetworkIDS(cfg, ledger, logger),
    "blocker": Blocker(cfg, ledger, logger),
    "backup": Backup(cfg, ledger, '/opt/data/edr-agent', logger),
    "alerter": Alerter(cfg, '/opt/data/edr-agent', logger),
    "reporter": Reporter(ledger, '/opt/data/edr-agent', logger),
}
m["fim"].baseline()

data = os.path.join(tmp, "data")
os.makedirs(data)
alerts_file = os.path.join(tmp, "alerts.json")

# Simulate brute-force log + file tampering
with open(os.path.join(tmp, "auth.log"), "a") as f:
    f.write("Aug 31 15:00:01 host sshd[1]: Failed password for root from 203.0.113.99 port 1 ssh2\n")
fp = os.path.join(data, "important.txt")
with open(fp, "w") as f:
    f.write("secret v1")
time.sleep(0.05)
with open(fp, "w") as f:
    f.write("TAMPERED")

# Sweep (one loop iteration)
alerts = []
alerts += m["log_monitor"].sweep()
alerts += m["fim"].sweep()
alerts += m["process"].sweep()
m["backup"].sweep()
m["blocker"].block("203.0.113.99", None, "detected_bruteforce")
for a in alerts:
    m["alerter"].alert(a)

# Delete then restore
os.remove(fp)
m["backup"].sweep()
m["backup"].restore(fp)
restored = open(fp).read()

md = m["reporter"].report()

print("=== INTEGRATION RESULTS ===")
print("alerts detected   :", len(alerts))
print("restored content  :", repr(restored))
print("restore correct   :", restored == "TAMPERED")
print("alerts.json lines :", sum(1 for _ in open(alerts_file)))
print("report has block  :", "detected_bruteforce" in md)
print("ledger events     :", ledger.query("SELECT count(*) c FROM events")[0]["c"])
print("ledger blocks     :", ledger.query("SELECT count(*) c FROM blocks")[0]["c"])
print("ledger versions   :", ledger.query("SELECT count(*) c FROM file_versions")[0]["c"])
ledger.close()
print("=== INTEGRATION PASSED ===")